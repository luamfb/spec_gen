// Copyright (C) 2026 Luana C. M. de F. Barbosa
//
// This file is part of spec_gen.
//
// spec_gen is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 only.
//
// spec_gen is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with spec_gen. If not, see <https://www.gnu.org/licenses/>.

use std::{
    io,
    ffi::{
        CStr,
    },
};

use nix::{
    libc,
    unistd::{self, ForkResult, Pid},
    sys::{
        personality::{self, Persona},
        ptrace,
        wait,
    },
};


pub fn fork_exec<S: AsRef<CStr>>(cmd: &CStr, argv: &[S]) {
    let orig_persona = personality::get()
        .expect("failed to get original persona");

    match unsafe {unistd::fork()} {
        Err(_) => panic!("fork() failed!"),
        Ok(ForkResult::Child) => {
            child(cmd, argv, orig_persona);
        },
        Ok(ForkResult::Parent {child : child_pid}) => {
            parent(child_pid);
        },
    }
}

fn child<S: AsRef<CStr>>(cmd: &CStr, argv: &[S], orig_persona: Persona) {
    if let Err(_) = ptrace::traceme() {
        async_safe_die(b"traceme() failed!\n");
    }

    let new_persona = Persona::union(orig_persona,
        Persona::ADDR_NO_RANDOMIZE);

    // note: must be set before exec'ing
    if let Err(_) = personality::set(new_persona) {
        async_safe_die(b"personality() failed!\n");
    }

    let Err(_) = unistd::execv(cmd, argv);

    // if we're still here, an error occurred
    async_safe_die(b"execv() failed!\n");
}

fn parent(child_pid: Pid) {
    println!("child PID: {}", child_pid);
    wait::waitpid(child_pid, None)
        .expect("waipid() failed!");
    ptrace::cont(child_pid, None)
        .expect("ptrace::cont() failed!");
    wait::waitpid(child_pid, None)
        .expect("waipid() failed!");
}

// should only use async-safe functions: see signal-safety(7) for a list of them
fn async_safe_die(msg: &[u8]) {
    unistd::write(io::stderr(), msg).ok();
    unsafe { libc::_exit(1); }
}
