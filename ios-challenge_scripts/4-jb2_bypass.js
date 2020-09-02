var jailbreakPaths = [
	"/etc/apt",
	"/Library/MobileSubstrate/MobileSubstrate.dylib",
	"/Applications/Cydia.app",
	"/Applications/blackra1n.app",
	"/Applications/FakeCarrier.app",
	"/Applications/Icy.app",
	"/Applications/IntelliScreen.app",
	"/Applications/MxTube.app",
	"/Applications/RockApp.app",
	"/Applications/SBSetttings.app",
	"/Applications/WinterBoard.app",
	"/usr/sbin/sshd",
	"/private/var/tmp/cydia.log",
	"/usr/binsshd",
	"/usr/libexec/sftp-server",
	"/Systetem/Library/LaunchDaemons/com.ikey.bbot.plist",
	"/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
	"/Library/MobileSubstrate/MobileSubstrate.dylib",
	"/var/log/syslog",
	"/bin/bash",
	"/bin/sh",
	"/etc/ssh/sshd_config",
	"/usr/libexec/ssh-keysign"
        ];

const ptrace_ptr = Module.findExportByName(null, 'ptrace');
Interceptor.attach(ptrace_ptr, {
  onEnter: function (args) {
    console.log('ptrace invoked...');
    console.log('Original args => 0: '+args[0]+' 1: '+ args[1]+ ' 2: '+ args[2]);
    args[0] = ptr(-1);
    console.log('Modified args => 0: '+args[0]+' 1: '+ args[1]+ ' 2: '+ args[2]);
  }
});

var hook = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
Interceptor.attach(hook.implementation, {
  onEnter: function (args) {
    this.jailbreak_detection = false;
    var path = ObjC.Object(args[2]).toString();
    var i = jailbreakPaths.length;
    while (i--) {
          if (jailbreakPaths[i] == path) {
              console.log("Jailbreak detection => Trying to read path: "+path);
              this.jailbreak_detection = true;
          }
    }
  },
  onLeave: function (retval) {
    if (this.jailbreak_detection) {
      retval.replace(0x00);
      console.log("Jailbreak detection bypassed!");
    }
  }
});

var hook = ObjC.classes.NSString["- writeToFile:atomically:encoding:error:"];
Interceptor.attach(hook.implementation, {
  onEnter: function (args) {
	  var  path = ObjC.Object(args[2]).toString(); 
    this.jailbreak_detection = false;
		if (path.indexOf("private") >= 0) {
      console.log("Jailbreak detection => Trying to write path: "+path);
			this.jailbreak_detection = true;
			this.error = args[5];
		}
	},
	onLeave: function (retval) {
	  if(this.jailbreak_detection) {
  		var error = ObjC.classes.NSError.alloc();
			Memory.writePointer(this.error, error);
		  console.log("Jailbreak detection bypassed!");
	  }
  }
});

var hook = ObjC.classes.UIApplication["- canOpenURL:"];
Interceptor.attach(hook.implementation, {
  onEnter: function (args) {
	  var  url = ObjC.Object(args[2]).toString();
		this.jailbreak_detection = false;
		if (url.indexOf("cydia") >= 0) {
  		console.log("Jailbreak detection => Trying to use Cydia URL Schema: "+url);
			this.jailbreak_detection = true;
		}
	},
	onLeave: function (retval) {
	  if(this.jailbreak_detection) {
		  retval.replace(0x00);
			console.log("Jailbreak detection bypassed!");
		}
	}
});
