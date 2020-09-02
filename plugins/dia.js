const specialChars = '`${}~|;#@&<> ()%":!';

const commands = {
  'dia0': interceptArg0,
  'dia1': interceptArg1,
  'dia_1': interceptArg_1,
};

r2frida.pluginRegister('dia', function (name) {
  return commands[name];
});

function getPtr(p) {
  if (typeof p === 'string') {
    p = p.trim();
    return Module.findExportByName(null, p);
  }
}

function interceptArg (target, value) {
  const p = getPtr(target);
  return Interceptor.attach(p, {
    onEnter (args) {
    console.log('Original arg[0] => '+args[0]);
    args[0] = ptr(value);
    console.log('Modified arg[0] => '+args[0]);
    }
  });
}

function interceptArg0 (args) {
  return interceptArg(args[0], 0);
}

function interceptArg1 (args) {
  return interceptArg(args[0], 1);
}

function interceptArg_1 (args) {
  return interceptArg(args[0], -1);
}

