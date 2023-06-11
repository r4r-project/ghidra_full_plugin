package analyzeflowcode.analyzer;

import java.awt.BorderLayout;
import java.awt.Color;
import java.util.HashSet;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;

import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.exception.CancelledException;

public class SyscallAnalyzer extends FunctionAnalyzer {

	private static final String[] X86_64 = { "read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "sys_brk", "rt_sigaction", "rt_sigprocmask", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "epoll_create", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev", "kcmp", "finit_module", "sched_setattr", "sched_getattr", "seccomp", "getrandom", "memfd_create", "kexec_file_load", "bpf", "userfaultfd", "membarrier", "mlock2", "copy_file_range", "pkey_mprotect", "pkey_alloc", "pkey_free" };
	private HashSet<String> syscalls = new HashSet<>();
	private JPanel panel;
	private JTextArea area;
	
	public SyscallAnalyzer() {
		this.panel = new JPanel(new BorderLayout());
		this.area  = new JTextArea();
		this.panel.setBorder(BorderFactory.createLineBorder(Color.BLACK));
		this.panel.add(new JLabel(this.getName()), BorderLayout.NORTH);
		this.panel.add(this.area, BorderLayout.CENTER);
	}
	
	@Override
	public int getPriority() {
		return 256;
	}

	@Override
	public String getName() {
		return "Syscalls Finded";
	}

	@Override
	public String getDescription() {
		return "Finded syscalls";
	}

	@Override
	public JPanel getComponent() {
		this.area.setText(String.join("\n", this.syscalls));
		return this.panel;
	}

	@Override
	protected boolean isAnalysable(Function function, boolean remote) {
		return function.getProgram().getLanguage().getProcessor().toString().equals("x86")
				&&
			   function.getProgram().getLanguage().getLanguageDescription().getSize() == 64;
	}

	@Override
	protected void update(Function function, FlatProgramAPI flatProgramApi) {
		long        end      = function.getBody().getMaxAddress().getOffset();
		Instruction curInstr = flatProgramApi.getFirstInstruction(function);
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(true);
		SymbolicPropogator symEval = new SymbolicPropogator(function.getProgram());
		try {
			int id = function.getProgram().startTransaction(this.getDescription());
			symEval.flowConstants(function.getEntryPoint(), function.getBody(), eval, true, flatProgramApi.getMonitor());
			function.getProgram().endTransaction(id, true);
		} catch (CancelledException e1) {}

		if(curInstr == null) { return; }
		
		do {
			if(curInstr.getMnemonicString().equals("SYSCALL")) {
				Value val = symEval.getRegisterValue(curInstr.getAddress(), function.getProgram().getLanguage().getRegister("RAX"));
				if(val != null) { this.syscalls.add(X86_64[(int)val.getValue()]); }
				else            { this.syscalls.add("unknow_syscall_at_" + curInstr.getAddress().toString()); }
			}
			
			curInstr = curInstr.getNext();
		} while(curInstr.getAddress().getOffset() < end);
		
	}

}
