import Tesseract from "tesseract.js";

declare global {
  interface Window {
    clearBeaconImageOcr?: (
      image: HTMLCanvasElement,
      language: string,
      onProgress: (status: string, progress: number) => void,
    ) => Promise<string>;
  }
}

let worker: Tesseract.Worker | undefined;
let workerLanguage = "";

window.clearBeaconImageOcr = async (image, language, onProgress) => {
  if (!worker || workerLanguage !== language) {
    await worker?.terminate();
    worker = await Tesseract.createWorker(language, 1, {
      workerPath: "/assets/ocr/worker.min.js",
      corePath: "/assets/ocr/tesseract-core-lstm.wasm.js",
      langPath: "https://tessdata.projectnaptha.com/4.0.0_fast",
      gzip: true,
      workerBlobURL: false,
      logger: ({ status, progress }) => onProgress(status, progress),
    });
    workerLanguage = language;
  }

  try {
    const result = await worker.recognize(image);
    return result.data.text.trim();
  } catch (error) {
    await worker.terminate();
    worker = undefined;
    workerLanguage = "";
    throw error;
  }
};
