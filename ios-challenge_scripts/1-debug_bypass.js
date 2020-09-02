const ptrace_ptr = Module.findExportByName(null, 'ptrace');
Interceptor.attach(ptrace_ptr, {
  onEnter: function (args) {
    console.log('ptrace invoked. Disabling it...');
    console.log('Original args => 0: '+args[0]+' 1: '+ args[1]+ ' 2: '+ args[2]);
    args[0] = ptr(-1);
    console.log('Modified args => 0: '+args[0]+' 1: '+ args[1]+ ' 2: '+ args[2]);
  }
});

const getppid_ptr = Module.findExportByName(null, 'getppid');
Interceptor.attach(getppid_ptr, {
  onLeave: function (retval) {
      console.log('ppid invoked. Disabling it...');
      retval.replace(0x01);
  }
});

const sysctl_ptr = Module.findExportByName(null, '__sysctl');
Interceptor.attach(sysctl_ptr, {
  onEnter: function (args) {
    this.kinfo = this.context.x2;
  },
  onLeave: function (retval) {
    const p = this.kinfo.add(32);
    const p_flag = p.readInt() & 0x800;
    if (p_flag === 0x800) {
      console.log('sysctl invoked. Disabling it...');
      p.writeInt(0);
    }
  }
});


const tamper_libs = [
  "Substrate",
  "cycript",
  "SSLKillSwitch",
  "SSLKillSwitch2",
  "frida"
];


const strstr_ptr = Module.findExportByName(null, 'strstr');
Interceptor.attach(strstr_ptr, {
  onEnter: function (args) {
    var i = tamper_libs.length;
    this.using_tamper_lib = false;
    while (i--) {   
      var lib = args[1].readUtf8String();
      if (lib == tamper_libs[i]) {
        console.log(`strstr invoked using ${lib}. Disabling it...`);
        this.using_tamper_lib = true;
      }
    }
  },
  onLeave: function (retval) {
      if (this.using_tamper_lib) {
        retval.replace(0x00);
      }
  }
});

