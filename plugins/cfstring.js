const specialChars = '`${}~|;#@&<> ()%":!';

const commands = {
  'cfstringj': cfstringJSON,
  'cfstring*': cfstringR2
};

r2frida.pluginRegister('cfstring', function (name) {
  return commands[name];
});

function cfstringJSON (args) {
  let complete = 0;
  const result = [];
  return new Promise((resolve, reject) => {
    r2frida.hostCmd('?v $$').then(res => {
      const header = headerFromOffset(ptr(res));
      console.log('header at', header);
      const segs = getSegments(header);
      for (const seg of segs) {
        if (seg.name === '__DATA') {
          const sects = getSections(seg);
          for (const sect of sects) {
            if (sect.name === '__cfstring') {
              parseCFString(sect, result);
              if (complete++ === 1) {
                resolve(result);
                return;
              }
            } else if (sect.name === '__objc_selrefs') {
              parseSelRefs(sect, result);
              if (complete++ === 1) {
                resolve(result);
                return;
              }
            }
          }
          break;
        }
      }

      resolve(result);
    }).catch(reject);
  });
}

function cfstringR2 (args) {
  return cfstringJSON(args).then(strs => {
    return strs.map(str => {
      if (str.cstring !== undefined) {
        return `f str.cstr.${sanitizeString(str.value)} ${str.length} ${str.address}`;
      } else {
        return `f str.sel.${sanitizeString(str.value)} ${str.length} ${str.address}`;
      }
    }).join('\n');
  });
}

function sanitizeString (str) {
  return str.split('').map(c => specialChars.indexOf(c) === -1 ? c : '_').join('').replace(/\s+/g, '');
}

function parseCFString (sect, result) {
  let cursor = sect.vmaddr;
  const end = cursor.add(sect.vmsize);
  while (cursor.compare(end) < 0) {
    if (cursor.readPointer().equals(ptr('0x00000000000007c8'))) {
      result.push({
        address: cursor.sub(8),
        value: cursor.add(8).readPointer().readUtf8String(),
        cstring: cursor.add(8).readPointer(),
        length: cursor.add(16).readU32()
      });
      cursor = cursor.add(24);
    } else {
      cursor = cursor.add(8);
    }
  }
}

function parseSelRefs (sect, result) {
  let cursor = sect.vmaddr;
  const end = cursor.add(sect.vmsize);
  while (cursor.compare(end) < 0) {
    try {
      const selPtr = cursor.readPointer();
      const value = selPtr.readUtf8String();
      result.push({
        address: cursor,
        value,
        length: value.length
      });
    } catch (e) {
    }
    cursor = cursor.add(Process.pointerSize);
  }
}

function headerFromOffset (off) {
  let cursor = trunc4k(off);
  while (cursor.readU32() !== 0xfeedfacf) {
    cursor = cursor.sub(0x1000);
  }
  return cursor;
}

function getSegments (header) {
  var ncmds = header.add(0x10).readU32();
  var cursor = header.add(0x20);
  var cputype = header.add(4).readU32();
  if (cputype !== 0x0100000c) {
    console.log('sorry not a 64-bit app');
    return [];
  }

  var LC_SEGMENT_64 = 0x19;
  var segs = [];
  var slide = 0;

  while (ncmds-- > 0) {
    var command = cursor.readU32();
    var cmdSize = cursor.add(4).readU32();

    if (command !== LC_SEGMENT_64) {
      cursor = cursor.add(cmdSize);
      continue;
    }

    var seg = {
      name: cursor.add(8).readUtf8String(),
      vmaddr: cursor.add(0x18).readPointer(),
      vmsize: cursor.add(0x18).add(8).readPointer(),
      nsects: cursor.add(64).readU32(),
      sections: cursor.add(72)
    };

    if (seg.name === '__TEXT') {
      slide = header.sub(seg.vmaddr);
    }

    segs.push(seg);
    cursor = cursor.add(cmdSize);
  }

  segs.forEach((seg) => {
    seg.vmaddr += slide;
    seg.slide = slide;
  });

  return segs;
}

function getSections (segment) {
  let { nsects, sections, slide } = segment;
  const sects = [];
  while (nsects--) {
    sects.push({
      name: sections.readUtf8String(),
      vmaddr: sections.add(32).readPointer().add(slide),
      vmsize: sections.add(40).readU64()
    });
    sections = sections.add(80);
  }
  return sects;
}

function trunc4k (x) {
  return x.and(ptr('0xfff').not());
}

/* globals ptr, r2frida */
