#!/usr/bin/env node

const EnvironmentBypass = {
  install(globalObj = globalThis) {
    const original = {
      getfenv: globalObj.getfenv,
      setfenv: globalObj.setfenv,
      debug: globalObj.debug ? { ...globalObj.debug } : null,
      string_dump: globalObj.string && globalObj.string.dump,
      loadstring: globalObj.loadstring,
      load: globalObj.load,
    };

    if (globalObj.debug) {
      globalObj.debug.getinfo = function (level, what) {
        return {
          source: "=[C]",
          short_src: "[C]",
          linedefined: -1,
          lastlinedefined: -1,
          what: "C",
          name: null,
          namewhat: "",
          nups: 0,
          currentline: -1,
          func: function () {},
          istailcall: false,
        };
      };
      globalObj.debug.traceback = function () {
        return "";
      };
      globalObj.debug.getlocal = function () {
        return null;
      };
      globalObj.debug.setlocal = function () {
        return null;
      };
      globalObj.debug.getupvalue = function () {
        return null;
      };
      globalObj.debug.setupvalue = function () {
        return null;
      };
    }

    globalObj.getfenv = function (f) {
      return globalObj;
    };

    globalObj.setfenv = function (f, env) {
      return f;
    };

    if (globalObj.string) {
      globalObj.string.dump = function (fn) {
        return "";
      };
    }

    if (typeof globalObj.loadstring === "function") {
      globalObj.loadstring = function (str, chunkname) {
        try {
          return original.loadstring
            ? original.loadstring(str, chunkname)
            : new Function(str);
        } catch (e) {
          return function () {};
        }
      };
    }

    globalObj.pcall = function (fn, ...args) {
      try {
        return [true, fn(...args)];
      } catch (e) {
        return [false, e];
      }
    };

    globalObj.xpcall = function (fn, errfn, ...args) {
      try {
        return [true, fn(...args)];
      } catch (e) {
        try {
          errfn(e);
        } catch (_) {}
        return [false, e];
      }
    };

    return function restore() {
      if (original.debug && globalObj.debug) {
        Object.assign(globalObj.debug, original.debug);
      }
      globalObj.getfenv = original.getfenv;
      globalObj.setfenv = original.setfenv;
      if (globalObj.string && original.string_dump) {
        globalObj.string.dump = original.string_dump;
      }
      globalObj.loadstring = original.loadstring;
      globalObj.load = original.load;
    };
  },

  createSandbox() {
    const sandbox = {
      _G: null,
      print: console.log.bind(console),
      type: (v) => typeof v,
      tostring: (v) => String(v),
      tonumber: (v) => Number(v),
      pairs: (t) => Object.entries(t)[Symbol.iterator](),
      ipairs: (t) => t[Symbol.iterator] ? t[Symbol.iterator]() : Object.values(t)[Symbol.iterator](),
      next: (t, k) => {
        const keys = Object.keys(t);
        const idx = k === undefined ? 0 : keys.indexOf(k) + 1;
        if (idx < keys.length) return [keys[idx], t[keys[idx]]];
        return null;
      },
      select: (idx, ...args) => {
        if (idx === "#") return args.length;
        return args[idx - 1];
      },
      unpack: (t) => (Array.isArray(t) ? t : Object.values(t)),
      error: (msg) => {
        throw new Error(msg);
      },
      assert: (cond, msg) => {
        if (!cond) throw new Error(msg || "assertion failed");
        return cond;
      },
      pcall: function (fn, ...args) {
        try {
          return [true, fn(...args)];
        } catch (e) {
          return [false, e.message || e];
        }
      },
      string: {
        dump: () => "",
        byte: (s, i) => s.charCodeAt((i || 1) - 1),
        char: (...codes) => String.fromCharCode(...codes),
        find: (s, pat) => {
          const m = s.match(new RegExp(pat));
          return m ? m.index + 1 : null;
        },
        sub: (s, i, j) => s.substring(i - 1, j),
        len: (s) => s.length,
        format: (fmt, ...args) => {
          let i = 0;
          return fmt.replace(/%[sd]/g, () => String(args[i++]));
        },
        rep: (s, n) => s.repeat(n),
        reverse: (s) => s.split("").reverse().join(""),
        lower: (s) => s.toLowerCase(),
        upper: (s) => s.toUpperCase(),
        gsub: (s, pat, repl) => s.replace(new RegExp(pat, "g"), repl),
      },
      table: {
        insert: (t, v) => t.push(v),
        remove: (t, i) => t.splice((i || t.length) - 1, 1)[0],
        concat: (t, sep) => t.join(sep || ""),
        sort: (t, cmp) => t.sort(cmp),
      },
      math: Math,
      bit: {
        band: (a, b) => a & b,
        bor: (a, b) => a | b,
        bxor: (a, b) => a ^ b,
        bnot: (a) => ~a,
        lshift: (a, n) => a << n,
        rshift: (a, n) => a >> n,
        arshift: (a, n) => a >> n,
      },
      debug: {
        getinfo: () => ({
          source: "=[C]",
          short_src: "[C]",
          linedefined: -1,
          lastlinedefined: -1,
          what: "C",
        }),
        traceback: () => "",
        getlocal: () => null,
        setlocal: () => null,
        getupvalue: () => null,
        setupvalue: () => null,
      },
    };
    sandbox._G = sandbox;
    sandbox.getfenv = () => sandbox;
    sandbox.setfenv = (f, e) => f;
    return sandbox;
  },
};

if (typeof module !== "undefined") {
  module.exports = EnvironmentBypass;
}

if (require.main === module) {
  const restore = EnvironmentBypass.install();
  console.log("Environment bypass installed");
  console.log("Sandbox created:", !!EnvironmentBypass.createSandbox());
}
