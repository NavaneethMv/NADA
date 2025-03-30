import { useState } from "react";
import { useLocation } from "react-router-dom";
import { Routes, Route } from "react-router-dom";
import Topbar from "./scenes/global/Topbar";
import Sidebar from "./scenes/global/Sidebar";
import Dashboard from "./scenes/dashboard";
import Bar from "./scenes/bar";
import Line from "./scenes/line";
import Pie from "./scenes/pie";
import FAQ from "./scenes/faq";
import WelcomePage from "./WelcomePage";
import { CssBaseline, ThemeProvider } from "@mui/material";
import { ColorModeContext, useMode } from "./theme";
import PrivateRoute from "./PrivateRoute"; 

function App() {
  const [theme, colorMode] = useMode();
  const [isSidebar, setIsSidebar] = useState(true);
  const location = useLocation(); // ✅ Get the current route

  // ✅ Check if the current page is the Welcome Page
  const isWelcomePage = location.pathname === "/";

  return (
    <ColorModeContext.Provider value={colorMode}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <div className="app">
          {/* ✅ Hide Sidebar on Welcome Page */}
          {!isWelcomePage && <Sidebar isSidebar={isSidebar} />}
          <main className="content">
            {/* ✅ Hide Topbar on Welcome Page (Optional) */}
            {!isWelcomePage && <Topbar setIsSidebar={setIsSidebar} />}
            
            <Routes>
              <Route path="/" element={<WelcomePage />} />
              <Route element={<PrivateRoute />}>
                  <Route path="/dashboard" element={<Dashboard />} />
                  <Route path="/bar" element={<Bar />} />
                  <Route path="/pie" element={<Pie />} />
                  <Route path="/line" element={<Line />} />
                  <Route path="/faq" element={<FAQ />} />
              </Route>
            </Routes>
          </main>
        </div>
      </ThemeProvider>
    </ColorModeContext.Provider>
  );
}

export default App;