import jsQR from "jsqr";

declare global {
  interface Window {
    jsQR?: typeof jsQR;
  }
}

window.jsQR = jsQR;
