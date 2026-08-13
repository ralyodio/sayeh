import init, {
  analyse,
  capacity,
  hidePasswordFile,
  hidePasswordText,
  probeAnalyse,
  probeGenerate,
  revealPassword,
  scan,
  stripSafe,
} from "./pkg/sayeh_wasm.js";

await init();

self.onmessage = ({ data }) => {
  try {
    const { operation, args } = data;
    let result;
    switch (operation) {
      case "hide-text":
        result = JSON.parse(hidePasswordText(...args));
        break;
      case "hide-file":
        result = JSON.parse(hidePasswordFile(...args));
        break;
      case "reveal":
        result = JSON.parse(revealPassword(...args));
        break;
      case "scan":
        result = { scan: JSON.parse(scan(args[0])), analysis: JSON.parse(analyse(args[0])) };
        break;
      case "strip":
        result = stripSafe(args[0]);
        break;
      case "capacity":
        result = JSON.parse(capacity(...args));
        break;
      case "probe-generate":
        result = probeGenerate();
        break;
      case "probe-analyse":
        result = JSON.parse(probeAnalyse(args[0]));
        break;
      default:
        throw new Error(`Unknown worker operation: ${operation}`);
    }
    self.postMessage({ ok: true, result });
  } catch (error) {
    self.postMessage({ ok: false, error: String(error) });
  }
};
