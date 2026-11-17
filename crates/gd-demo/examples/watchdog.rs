//! `cargo run --locked --example watchdog`: watch Guard Dog catch a leak.
//!
//! Five scenes, each a planted attack, each run by the real code: the safe
//! renderer for outside text and Judge C's egress checker. The
//! scenes live in `src/lib.rs`; this file only prints them. The browser demo
//! (`docs/demo/`) animates the very same events from a WebAssembly build.
//!
//! No network, no real secrets: every key and address is generated. Add
//! `--fast` to skip the pauses (they're only there so you can read along).
//! If a check ever fails to catch its planted case, this says "MISSED" and
//! exits with an error.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;

use gd_demo::{Event, all_caught, caught, missed, run, scenes, todos};

struct Show {
    color: bool,
    pause: Duration,
}

impl Show {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn line(&self, s: &str, beats: u32) {
        println!("{s}");
        std::io::stdout().flush().ok();
        std::thread::sleep(self.pause * beats);
    }

    fn print(&self, e: &Event) {
        match e {
            Event::Scene { n, title, story } => {
                println!();
                println!("{}", self.paint("1", &format!("Scene {n}: {title}")));
                self.line(&self.paint("2", story), 2);
            }
            Event::Step(text) => self.line(&format!("  {text}"), 1),
            Event::Show { label, text } => {
                self.line(&format!("  {label}:"), 1);
                self.line(&format!("    | {text}"), 1);
            }
            Event::Good(text) => self.line(&format!("  {} {text}", self.paint("32", "ok")), 1),
            Event::Caught(text) => {
                self.line(&format!("  {} {text}", self.paint("32;1", "caught.")), 1)
            }
            Event::Missed(text) => self.line(
                &format!(
                    "  {} {text} This is a bug; please report it.",
                    self.paint("41;1", "MISSED:")
                ),
                1,
            ),
            Event::Todo {
                title,
                arrives_with,
            } => self.line(
                &format!(
                    "  {} {title} (arrives with {arrives_with})",
                    self.paint("2", "TODO, not in yet:")
                ),
                0,
            ),
        }
    }
}

fn main() -> ExitCode {
    let fast = std::env::args().any(|a| a == "--fast");
    let tty = std::io::stdout().is_terminal();
    let show = Show {
        color: tty,
        pause: if fast || !tty {
            Duration::ZERO
        } else {
            Duration::from_millis(900)
        },
    };

    // Every scene runs first (it takes milliseconds); then we replay it slowly.
    let events = run();

    println!(
        "{}",
        show.paint(
            "1",
            "Guard Dog: a watchdog that doesn't trust what it reads, or what leaves the machine."
        )
    );
    show.line("Planted attacks. Everything is fake except the checks.", 2);
    let (todo_events, scene_events): (Vec<&Event>, Vec<&Event>) =
        events.iter().partition(|e| matches!(e, Event::Todo { .. }));
    for e in scene_events {
        show.print(e);
    }
    println!();
    println!("{}", show.paint("1", "Not in yet"));
    for e in todo_events {
        show.print(e);
    }

    println!();
    let total = scenes(&events);
    if !all_caught(&events) {
        println!(
            "{}",
            show.paint(
                "41;1",
                &format!(
                    "MISSED: {} of {total} planted case(s) were caught; {} were not. Please report this.",
                    caught(&events),
                    missed(&events)
                )
            )
        );
        return ExitCode::FAILURE;
    }
    println!(
        "{}",
        show.paint(
            "32;1",
            &format!(
                "{} of {total} planted cases caught. {} more scenes are waiting on code that isn't written yet.",
                caught(&events),
                todos(&events)
            )
        )
    );
    ExitCode::SUCCESS
}
