use ghostlock_extract::boot::BootImage;
use ghostlock_extract::kallsyms_finder;
use std::path::Path;

fn main() {
    let path = std::env::args().nth(1).expect("image path");
    let boot = BootImage::load(Path::new(&path)).expect("load boot image");
    let btf = boot.embedded_btf_at();
    let btf_at = btf.as_ref().map(|(offset, blob)| (*offset, blob.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, btf_at).expect("recover kallsyms");
    for name in [
        "_text", "commit_creds", "init_cred", "posix_timer_fn",
        "posix_timer_fn_", "common_timer_get", "posix_cpu_timer_set",
        "k_itimer", "sigqueue", "task_can_queue_signal",
    ] {
        if let Some(values) = ks.symbols.get(name) {
            for value in values {
                println!("{name} {value:#x}");
            }
        }
    }
    // dump all symbols for local grep
    let mut out = String::new();
    for (name, values) in &ks.symbols {
        for value in values {
            out.push_str(&format!("{value:016x} {name}\n"));
        }
    }
    std::fs::write("/tmp/android-kallsyms.txt", out).expect("write kallsyms dump");
    eprintln!("symbols={} dump=/tmp/android-kallsyms.txt", ks.symbols.len());
}
