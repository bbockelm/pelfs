import { createRoot } from "react-dom/client";
import { App } from "./App";
import "@svar-ui/react-filemanager/style.css";
import "./brand/brand.css";
import "./ui/app.css";

const el = document.getElementById("root");
if (el) createRoot(el).render(<App />);
