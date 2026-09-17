import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { PluginOutputWindow } from "./components/PluginOutputWindow";
import { applyPreferences, readPreferences } from "./lib/preferences";
import { isPluginOutputWindow } from "./lib/pluginOutputWindow";
import "./styles.css";

applyPreferences(readPreferences());

document.addEventListener(
  "contextmenu",
  (event) => {
    event.preventDefault();
  },
  { capture: true },
);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {isPluginOutputWindow() ? <PluginOutputWindow /> : <App />}
  </StrictMode>,
);
