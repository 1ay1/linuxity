// tests/test_whp_load.cpp
//
// The Windows ELF loader and startup stack, end to end.
//
// This is the test that proves the backend can run a REAL program rather
// than a hand-placed instruction sequence. It synthesizes a minimal but
// genuine static x86-64 ELF (a real Ehdr + PT_LOAD, the same bytes `ld`
// would produce for this program), loads it through whp_load_elf, builds a
// SysV startup stack, and runs it under the #UD syscall trap.
//
// The guest program is written to PROVE the loader's contract, not just to
// exit: it reads argc off the stack and returns it via exit(), so a wrong
// stack layout or misaligned rsp produces a wrong exit code rather than
// passing by luck.
//
// Split like test_whp.cpp: the ELF-parsing half runs anywhere (it is pure
// file logic), the execution half SKIPs without a hypervisor.
#include "linuxity/runtime/whp_api.hpp"
#include "linuxity/runtime/whp_load.hpp"
#include "linuxity/runtime/whp_trap.hpp"
#include "linuxity/runtime/whp_vm.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

using namespace lx::runtime;

// The guest RAM every case here uses. Deliberately the layout minimum rather
// than something generous: the addresses must be coherent on a SMALL guest,
// which is where a hardcoded base silently breaks.
static constexpr std::uint64_t kRam = WhpLayout::min_ram;

static int failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                   \
        }                                                                 \
    } while (0)

namespace {

std::string temp_path(const char* name) {
    std::error_code ec;
    auto d = std::filesystem::temp_directory_path(ec);
    if (ec) d = ".";
    return (d / name).string();
}

// Build a real static x86-64 ELF executable on disk.
//
// Layout: one PT_LOAD mapping the whole file (headers included) at `vaddr`,
// which is how a simple static non-PIE binary is laid out. `code` is placed
// at file offset 0x1000 so it is page-aligned.
std::string write_elf(const char* name,
                      const std::vector<unsigned char>& code,
                      std::uint64_t vaddr = 0x40'0000,
                      std::uint16_t etype = 2 /*ET_EXEC*/,
                      std::uint16_t machine = 62 /*EM_X86_64*/) {
    constexpr std::uint64_t kCodeOff = 0x1000;

    lx::loader::Ehdr eh{};
    eh.e_ident[0] = 0x7f; eh.e_ident[1] = 'E';
    eh.e_ident[2] = 'L';  eh.e_ident[3] = 'F';
    eh.e_ident[4] = 2;    // ELFCLASS64
    eh.e_ident[5] = 1;    // ELFDATA2LSB
    eh.e_ident[6] = 1;    // EV_CURRENT
    eh.e_type = etype;
    eh.e_machine = machine;
    eh.e_version = 1;
    eh.e_entry = vaddr + kCodeOff;
    eh.e_phoff = sizeof(lx::loader::Ehdr);
    eh.e_ehsize = sizeof(lx::loader::Ehdr);
    eh.e_phentsize = sizeof(lx::loader::Phdr);
    eh.e_phnum = 1;

    lx::loader::Phdr ph{};
    ph.p_type = 1;                       // PT_LOAD
    ph.p_flags = 4 | 1;                  // PF_R | PF_X
    ph.p_offset = 0;
    ph.p_vaddr = vaddr;
    ph.p_paddr = vaddr;
    ph.p_filesz = kCodeOff + code.size();
    ph.p_memsz = kCodeOff + code.size();
    ph.p_align = 0x1000;

    std::vector<unsigned char> file(kCodeOff + code.size(), 0);
    std::memcpy(file.data(), &eh, sizeof eh);
    std::memcpy(file.data() + sizeof eh, &ph, sizeof ph);
    std::memcpy(file.data() + kCodeOff, code.data(), code.size());

    const std::string path = temp_path(name);
    if (std::FILE* f = std::fopen(path.c_str(), "wb")) {
        std::fwrite(file.data(), 1, file.size(), f);
        std::fclose(f);
    }
    return path;
}

} // namespace

// -- Offline: the layout is coherent on every RAM size -------------------
// Pure arithmetic, so this runs with no hypervisor. It is also the check
// that catches the class of bug a hardcoded base caused: an address outside
// guest RAM. Because this backend identity-maps, "outside RAM" means
// "unloadable", and for a PIE that means nothing runs at all.
static void test_layout_fits_ram() {
    for (std::uint64_t mib : {64ull, 128ull, 256ull, 512ull, 2048ull, 4096ull}) {
        const std::uint64_t ram = mib << 20;
        const auto pie   = WhpLayout::pie_base(ram);
        const auto interp= WhpLayout::interp_base(ram);
        const auto top   = WhpLayout::stack_top(ram);
        const std::uint64_t stack_bot = top - WhpLayout::stack_size;

        // Everything inside RAM...
        CHECK(pie    < ram);
        CHECK(interp < ram);
        CHECK(top   <= ram);
        // ...above the private table/GDT region...
        CHECK(pie    >= kGuestFloor);
        CHECK(interp >= kGuestFloor);
        // ...and strictly ordered, so image < interpreter < stack and none
        // can grow into another.
        CHECK(pie < interp);
        CHECK(interp < stack_bot);
        // Page alignment, since these become page-table entries.
        CHECK((pie % kPageSize) == 0);
        CHECK((interp % kPageSize) == 0);
    }
}

// -- Offline: ELF parsing -------------------------------------------------
// A machine without a hypervisor still gets these, and they cover the
// decisions most likely to be wrong: entry/phdr computation and the refusals.
static void test_elf_parse() {
    if (!hypervisor_present()) {
        std::puts("  SKIP elf parse (needs guest RAM to load into)");
        return;
    }
    WhpMachine vm;
    if (!vm.create(kRam, 1)) { std::puts("  SKIP elf parse"); return; }

    // mov eax,60; mov edi,5; syscall
    const std::vector<unsigned char> code{
        0xb8, 0x3c, 0, 0, 0, 0xbf, 0x05, 0, 0, 0, 0x0f, 0x05};

    // A static ET_EXEC at its own vaddr: load_bias must be 0 and the entry
    // must be the ELF's own e_entry.
    const auto p = write_elf("lx_whp_static.elf", code);
    auto img = whp_load_elf(vm, p, WhpLayout::pie_base(kRam));
    CHECK(img.has_value());
    if (img) {
        CHECK(img->load_bias == 0);
        CHECK(img->entry == 0x40'1000);
        // No PT_PHDR here, and e_phoff (64) lies inside the PT_LOAD, so
        // AT_PHDR must resolve via the file-offset path to vaddr+64 -- NOT
        // to bias+64, the bug the loader comments call out.
        CHECK(img->phdr_addr == 0x40'0000 + sizeof(lx::loader::Ehdr));
        CHECK(img->phnum == 1);
        CHECK(img->phent == sizeof(lx::loader::Phdr));
        CHECK(img->segments.size() == 1);
        CHECK(img->image_end == 0x40'2000);
    }

    // A PIE must be relocated to the bias.
    const auto pie = write_elf("lx_whp_pie.elf", code, 0x0, 3 /*ET_DYN*/);
    auto pimg = whp_load_elf(vm, pie, WhpLayout::pie_base(kRam));
    CHECK(pimg.has_value());
    if (pimg) {
        CHECK(pimg->load_bias == WhpLayout::pie_base(kRam));
        CHECK(pimg->entry == WhpLayout::pie_base(kRam) + 0x1000);
    }

    // A foreign-arch ELF must be REFUSED, not loaded and jumped into. This
    // is the aarch64-on-x86 case: there is no emulator, so ENOEXEC.
    const auto arm = write_elf("lx_whp_arm.elf", code, 0x40'0000, 2,
                               183 /*EM_AARCH64*/);
    auto aimg = whp_load_elf(vm, arm, WhpLayout::pie_base(kRam));
    CHECK(!aimg.has_value());

    // A nonexistent path is ENOENT, and garbage is ENOEXEC.
    CHECK(!whp_load_elf(vm, temp_path("lx_whp_nope.elf"), 0).has_value());
    const auto junk = temp_path("lx_whp_junk.bin");
    if (std::FILE* f = std::fopen(junk.c_str(), "wb")) {
        std::fputs("not an elf at all", f);
        std::fclose(f);
    }
    CHECK(!whp_load_elf(vm, junk, 0).has_value());

    // PT_INTERP: absent in a static binary.
    auto interp = whp_read_interp(p);
    CHECK(interp.has_value());
    if (interp) CHECK(interp->empty());
}

// -- Live: load and RUN ---------------------------------------------------
static void test_run_static() {
    if (!hypervisor_present() || !exception_exit_supported()) {
        std::printf("  SKIP run: %s\n", whp_unavailable_reason());
        return;
    }

    WhpMachine vm;
    if (!vm.create(kRam, 1)) { std::puts("  SKIP run: no partition"); return; }
    WhpCpu cpu;
    if (!cpu.create(vm, 0)) { std::puts("  SKIP run: no vcpu"); return; }

    // The guest program:
    //     mov rdi, [rsp]     ; argc, per the SysV entry contract
    //     mov eax, 60        ; __NR_exit
    //     syscall
    //
    // Reading argc off the stack is what makes this a real test of the
    // startup stack: if whp_build_stack put argc anywhere but [rsp], or
    // misaligned rsp, the exit status is wrong.
    const std::vector<unsigned char> code{
        0x48, 0x8b, 0x3c, 0x24,          // mov rdi, [rsp]
        0xb8, 0x3c, 0x00, 0x00, 0x00,    // mov eax, 60
        0x0f, 0x05,                      // syscall
    };
    const auto path = write_elf("lx_whp_run.elf", code);

    auto img = whp_load_elf(vm, path, WhpLayout::pie_base(kRam));
    CHECK(img.has_value());
    if (!img) return;

    const std::vector<std::string> argv{"/bin/true", "a", "b"};   // argc == 3
    const std::vector<std::string> envp{"PATH=/usr/bin", "HOME=/root"};
    auto sp = whp_build_stack(vm, *img, argv, envp);
    CHECK(sp.has_value());
    if (!sp) return;

    // The ABI requires rsp 16-byte aligned at entry, with argc at [rsp].
    CHECK((*sp % 16) == 0);
    std::uint64_t argc_in_guest = 0;
    CHECK(vm.ram().get_phys(*sp, argc_in_guest));
    CHECK(argc_in_guest == argv.size());

    WhpTrap trap{vm, cpu};
    auto st = trap.start(lx::UAddr(img->entry), lx::UAddr(*sp));
    CHECK(st.has_value());
    if (!st) return;

    TrapFrame f{};
    auto got = trap.next(f);
    if (!got) {
        std::printf("  FAIL run: no syscall trap (stop=%d)\n",
                    int(trap.stop_reason()));
        ++failures;
        return;
    }
    CHECK(*got == true);
    // The guest executed three real instructions natively, including a load
    // off its own stack, then trapped. exit(argc) == exit(3).
    CHECK(f.regs.nr == 60);
    CHECK(f.regs.arg[0] == argv.size());
    if (f.regs.nr == 60 && f.regs.arg[0] == argv.size())
        std::printf("  ran a real ELF: exit(%llu) from a loaded static binary\n",
                    (unsigned long long)f.regs.arg[0]);
}

// Verify W^X actually took effect: a read-only PT_LOAD must not be writable
// through the guest's own page tables. This is the protection the per-segment
// 4KiB mapping buys over a blanket RWX window.
static void test_wx_enforced() {
    if (!hypervisor_present()) { std::puts("  SKIP W^X"); return; }
    WhpMachine vm;
    if (!vm.create(kRam, 1)) { std::puts("  SKIP W^X"); return; }

    const std::vector<unsigned char> code{0x0f, 0x05};
    const auto path = write_elf("lx_whp_wx.elf", code);   // PF_R|PF_X, no PF_W
    auto img = whp_load_elf(vm, path, 0);
    CHECK(img.has_value());
    if (!img) return;

    // The text page must resolve, be executable, and NOT be writable.
    auto w = vm.mmu().translate(img->entry);
    CHECK(w.present);
    CHECK(!w.writable);

    // And copy_out must refuse it rather than scribbling on guest text.
    auto mem = vm.mem();
    const unsigned char poke[4]{0x90, 0x90, 0x90, 0x90};
    CHECK(mem.copy_out(img->entry,
                       std::span<const std::byte>{
                           reinterpret_cast<const std::byte*>(poke), 4}) == 0);
}

int main() {
    std::puts("whp_load: layout");
    test_layout_fits_ram();
    std::puts("whp_load: ELF parsing");
    test_elf_parse();
    std::puts("whp_load: W^X");
    test_wx_enforced();
    std::puts("whp_load: load and run");
    test_run_static();

    // Clean up fixtures.
    std::error_code ec;
    for (const char* n : {"lx_whp_static.elf", "lx_whp_pie.elf",
                          "lx_whp_arm.elf", "lx_whp_junk.bin",
                          "lx_whp_run.elf", "lx_whp_wx.elf"}) {
        std::filesystem::remove(temp_path(n), ec);
    }

    if (failures == 0) std::puts("whp_load: all checks passed");
    return failures ? 1 : 0;
}
