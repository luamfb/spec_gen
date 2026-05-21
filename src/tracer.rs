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
    cell::Cell,
    collections::{HashMap, HashSet},
    default::Default,
    fmt::Display,
    fs,
    hash::{Hash, Hasher},
    io,
    ffi::{
        CStr,
    },
    process,
};

use anyhow::{
    bail,
    Context,
};

use log::{
    info,
    debug,
    error,
    warn,
};

use nix::{
    libc::{self, c_long, c_void},
    unistd::{self, ForkResult, Pid},
    sys::{
        personality::{self, Persona},
        ptrace::{self, regset},
        signal::{self, Signal},
        wait::{self, WaitStatus},
    },
};

use crate::{
    proc_maps,
    debug_info::{DebugInfo, VarLocation},
};

// TODO other architectures
const X86_BREAK_INSTR : c_long = 0xcc; // int 3
const X86_BREAK_INSTR_SIZE : u64 = 1; // size in bytes

pub fn fork_exec<S: AsRef<CStr>>(cmd: &CStr, argv: &[S]) {
    let orig_persona = personality::get()
        .expect("failed to get original persona");

    match unsafe {unistd::fork()} {
        Err(_) => panic!("fork() failed!"),
        Ok(ForkResult::Child) => {
            child(cmd, argv, orig_persona);
        },
        Ok(ForkResult::Parent {child : child_pid}) => {
            parent(child_pid, cmd);
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

fn parent(child_pid: Pid, child_path: &CStr) {
    info!("child PID: {}", child_pid);

    // child should have been sent a signal when calling execve()
    parent_unwrap_error(
        wait::waitpid(child_pid, None),
        "waitpid() failed!",
        child_pid);

    let child_path_str = parent_unwrap_error(
        child_path.to_str(),
        "child path has invalid UTF-8",
        child_pid);
    let bin_data = parent_unwrap_error(
        fs::read(child_path_str),
        &format!("failed to read file {}", child_path_str),
        child_pid);
    let mut tracer = parent_unwrap_error(
        Tracer::new(&bin_data, child_pid, child_path),
        "failed to create tracer",
        child_pid);

    parent_unwrap_error(
        tracer.set_fn_breakpoints(),
        "failed to set breakpoints",
        child_pid);

    loop {
        let child_running = parent_unwrap_error(
            tracer.resume_child_proc(),
            "failed to resume child process",
            child_pid);
        if !child_running {
            break;
        }
    }
}

// kills the child process on error.
fn parent_unwrap_error<V, E: Display>(
    res: Result<V, E>,
    msg: &str,
    child_pid: Pid) -> V {

    match res {
        Ok(val) => val,
        Err(e) => {
            error!("{}: {}", msg, e);
            signal::kill(child_pid, Signal::SIGKILL)
                .expect("failed to kill traced process");
            process::exit(0)
        },
    }
}

/// data associated with a function in the child process
#[derive(Default, PartialEq, Eq)]
struct FnData {
    /// function's name
    pub name: String,
    /// original instruction prior to setting breakpoint at the beginning of
    /// this function. None if the breakpoint haven't been set yet.
    pub original_instr: Cell<Option<c_long>>,
    /// the function's parameters and their location
    pub params: Vec<(String, VarLocation)>,
}

impl Hash for FnData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

/// Currently supported architectures.
#[derive(Debug)]
enum Architecture {
    X86_64,
    I386,
}

pub struct Tracer {
    /// architecture of the binary being analyzed.
    arch: Architecture,

    /// beginning of child process's .text section
    text_section_addr: u64,

    /// the function data for each function, indexed by their addresses
    /// on the child process.
    fn_data_per_addr: HashMap<u64, FnData>,

    /// function data for functions whose address is unknown
    /// (normally library calls)
    fn_data_unknown_addr: HashSet<FnData>,

    /// Child process's PID
    child_pid: Pid,

    /// debug information associated with child process binary
    debug_info: DebugInfo,
}

impl Tracer {
    pub fn new(data: &[u8], child_pid: Pid, child_path: &CStr)
            -> anyhow::Result<Self> {
        let proc_maps_path = format!("/proc/{}/maps", child_pid);
        let text_section_addr = proc_maps::get_text_section_start_addr(
            &proc_maps_path, child_path.to_bytes())?;

        let debug_info = DebugInfo::new(&data)
            .context("failed to parse debug information from binary")?;

        let arch = match debug_info.get_architecture() {
            object::Architecture::X86_64 => Architecture::X86_64,
            object::Architecture::I386 => Architecture::I386,
            unk_arch => bail!("unsupported CPU architecture {:?}", unk_arch),
        };
        debug!("Program's CPU architecture: {:?}", arch);

        let fn_debug_data = debug_info
            .get_all_func_name_and_addr()?;

        let mut fn_data_per_addr = HashMap::new();
        let mut fn_data_unknown_addr = HashSet::new();
        for entry_data in fn_debug_data.into_iter() {
            let fn_data = FnData {
                name: entry_data.name,
                params: entry_data.params.into_iter().collect(),
                ..Default::default() };
            match entry_data.addr {
                None => { fn_data_unknown_addr.insert(fn_data); },
                Some(low_pc_addr) => {
                    let addr = compute_fn_addr(text_section_addr, low_pc_addr);
                    debug!("associated function '{}' with address '{:#x}'",
                        fn_data.name, addr);
                    fn_data_per_addr.insert(addr, fn_data);
                },
            };
        }

        Ok(Tracer {
            arch,
            text_section_addr,
            fn_data_per_addr,
            fn_data_unknown_addr,
            child_pid,
            debug_info,
        })
    }

    /// Set a breakpoint at the beginning of each function that has a known address.
    pub fn set_fn_breakpoints(&mut self) -> anyhow::Result<()> {
        for (fn_addr, fn_data) in self.fn_data_per_addr.iter() {
            let addr = (*fn_addr) as *mut c_void;
            info!("Setting breakpoint at function '{}', address '{:?}'",
                fn_data.name, addr);
            let original_instr = ptrace::read(self.child_pid, addr)
                .context(format!("failed to read instruction from address {:?}",
                        addr))?;
            debug!("original instruction at {:?} is {:#x}",
                addr, original_instr);

            self.set_breakpoint_at(addr, original_instr)?;
            fn_data.original_instr.set(Some(original_instr));
        }
        Ok(())
    }

    /// Set a breakpoint at a given address.
    /// `original_instr` are the original instructions at this address.
    fn set_breakpoint_at(&self, addr: *mut c_void, original_instr: c_long)
            -> anyhow::Result<()> {
        // TODO verify which architecture we're running at and choose
        // the instruction accordingly
        let break_instr = X86_BREAK_INSTR;
        let break_instr_size = X86_BREAK_INSTR_SIZE;

        // since the architecture is little endian, we want to zero out the
        // N least significant bytes, where N is the size of the breakpoint
        // instruction in bytes.
        //
        let mask = -((break_instr_size as i64) << 8);
        let instr_with_bp = (original_instr & mask) | break_instr;

        debug!("Setting breakpoint: writing value {:#x} at {:?}",
            instr_with_bp, addr);

        ptrace::write(self.child_pid, addr, instr_with_bp)
            .context(format!("failed to write breakpoint instruction at {:?}",
                    addr))?;
        Ok(())
    }

    /// Resume child process, and if a breakpoint is hit, single-step it.
    /// Returns true if child process is still running, false if it terminated.
    pub fn resume_child_proc(&self) -> anyhow::Result<bool> {
        debug!("continuing child process");
        ptrace::cont(self.child_pid, None)
            .context("PTRACE_CONT operation failed")?;
        let wstatus = wait::waitpid(self.child_pid, None)
            .context("waitpid() failed")?;
        match wstatus {
            WaitStatus::Exited(_, exit_code) => {
                info!("child process exited with code {}", exit_code);
                Ok(false)
            },
            WaitStatus::Signaled(_, sig, _) => {
                info!("child process killed by signal {}", sig);
                Ok(false)
            },
            WaitStatus::Stopped(_, Signal::SIGTRAP)
            | WaitStatus::PtraceEvent(_, Signal::SIGTRAP, _) => {
                info!("child process stopped with SIGTRAP");
                self.single_step_breakpoint()?;
                Ok(true)
            },
            WaitStatus::Stopped(_, sig)
            | WaitStatus::PtraceEvent(_, sig, _) => {
                match sig {
                    Signal::SIGSEGV
                    | Signal::SIGTERM
                    | Signal::SIGINT
                    | Signal::SIGQUIT
                    | Signal::SIGABRT
                    | Signal::SIGILL => {
                        error!("child stopped by fatal signal {}", sig);
                        // pass the signal onto the child process so it may
                        // produce a core dump if required
                        if let Err(e) = signal::kill(self.child_pid, sig) {
                            warn!("failed to send signal {} to child: '{:?}'",
                                sig, e);
                        }
                        Ok(false)
                    },
                    _ => {
                        info!("child stopped by non-fatal signal {}", sig);
                        Ok(true)
                    },
                }
            },
            WaitStatus::Continued(_) => {
                warn!("waitpid() should not have reported 'Continued' status");
                Ok(true)
            },
            WaitStatus::StillAlive => {
                warn!("waitpid() should not have reported 'StillAlive' status");
                Ok(true)
            },
            _ => Ok(true),
        }
    }

    /// Restores the original instruction at the breakpoint's address,
    /// executes it, then reinserts the breakpoint.
    fn single_step_breakpoint(&self) -> anyhow::Result<()> {
        let regs = ptrace::getregs(self.child_pid)
            .context("PTRACE_GETREGS operation failed")?;

        // note: in x86, RIP points to the address of the next instruction
        // to be executed, so we need to subtract its size as well
        let addr_u64 = regs.rip - X86_BREAK_INSTR_SIZE;
        let addr = addr_u64 as *mut c_void;

        debug!("single-stepping breakpoint at address {:#x}", addr_u64);

        let fn_data = match self.fn_data_per_addr.get(&addr_u64) {
            None => bail!("no function associated with address {:x}", addr_u64),
            Some(data) => data,
        };

        self.print_fn_call(&fn_data)?;

        let original_instr = match fn_data.original_instr.get() {
            None => bail!("no original instruction saved for function {}",
                fn_data.name),
            Some(instr) => instr,
        };

        ptrace::write(self.child_pid, addr, original_instr)
            .context(format!("failed to restore original instruction at function {}, address {:?}",
                    fn_data.name, addr_u64))?;

        ptrace::step(self.child_pid, None)
            .context(format!(
                    "failed to single-step original instruction at function {}, address {:?}",
                    fn_data.name, addr_u64))?;
        // PTRACE_SINGLESTEP should stop to the child with a SIGTRAP:
        // wait for the signal to arrive
        let wstatus = wait::waitpid(self.child_pid, None)
            .context("failed to wait for child process")?;
        match wstatus {
            WaitStatus::Stopped(_, sig) => {
                info!("child stopped by signal {} after PTRACE_SINGLESTEP",
                    sig);
            },
            WaitStatus::PtraceEvent(_, Signal::SIGSTOP, _) => {
                info!("child stopped with SIGSTOP by ptrace event after PTRACE_SINGLESTEP");
            },
            _ => {
                error!("child not stopped after PTRACE_SINGLESTEP");
            },
        };

        self.set_breakpoint_at(addr, original_instr)?;
        Ok(())
    }

    fn print_fn_call(&self, fn_data: &FnData) -> anyhow::Result<()> {
        // TODO print local vars as well

        let general_regs = ptrace::getregs(self.child_pid)
            .context("PTRACE_GETREGS operation failed")?;

        let float_regs = ptrace::getregset::<regset::NT_PRFPREG>(
            self.child_pid)
            .context("PTRACE_GETREGSET operation failed")?;

        // number of the next available general purpose register
        let mut general_reg_index = 0;
        // same, for floating-point registers
        let mut float_reg_index = 0;
        print!("{}(", fn_data.name);
        for (param_name, param_loc) in fn_data.params.iter() {
            print!("{}", param_name);
            match self.arch {
                Architecture::X86_64 => {
                    let is_floating = match param_loc {
                        VarLocation::Register => false,
                        VarLocation::SseRegister => true,
                    };
                    if is_floating {
                        match float_regs.xmm_space.get(float_reg_index) {
                            Some(val) => print!(" = {},", f32::from_bits(*val)),
                            None => print!(", "),
                        };
                        float_reg_index += 1;
                    } else {
                        match unix_x86_64_call_conv_nth_reg(
                                &general_regs, general_reg_index) {
                            Some(val) => print!(" = {},", val),
                            None => print!(", "),
                        };
                        general_reg_index += 1;
                    }
                },
                Architecture::I386 => {
                    // TODO get arguments from stack
                    print!(", ");
                },
            };
        }
        println!(")");
        Ok(())
    }
}

/// Compute a function's address in a running process given the beginning of its
/// .text address and the DW_AT_low_pc attribute obtained from the debug
/// information.
/// This is effectively an OR of the two addresses, but one that only changes
/// the bits of text_section_addr when they belong to a leading zero hex digit:
///
/// ```
/// assert_eq!(compute_fn_addr(0x200, 0xff3), 0x2f3); // same as 0x200 | 0x0f3
/// ```
///
fn compute_fn_addr(text_section_addr: u64, low_pc_addr: u64) -> u64 {
    let mut mask = u64::MAX << 4;
    let mut new_mask = mask;
    while (new_mask & text_section_addr) == text_section_addr {
        mask = new_mask;
        new_mask = new_mask << 4;
    }
    // here, `mask` should be 0xff..f00..00, where the number of trailing zeros
    // is exactly the same as in text_section_addr.

    let capped_low_pc_addr = (!mask) & low_pc_addr;
    text_section_addr | capped_low_pc_addr
}

fn unix_x86_64_call_conv_nth_reg(regs: &libc::user_regs_struct, n: usize)
        -> Option<libc::c_ulonglong> {
    match n {
        0 => Some(regs.rdi),
        1 => Some(regs.rsi),
        2 => Some(regs.rdx),
        3 => Some(regs.rcx),
        4 => Some(regs.r8),
        5 => Some(regs.r9),
        _ => None,
    }
}

// should only use async-safe functions: see signal-safety(7) for a list of them
fn async_safe_die(msg: &[u8]) {
    unistd::write(io::stderr(), msg).ok();
    unsafe { libc::_exit(1); }
}
