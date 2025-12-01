import { useEffect } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Toaster } from "@/components/ui/sonner";
import { initTheme } from "@/stores";

function App() {
  useEffect(() => {
    initTheme();
  }, []);

  return (
    <>
      <AppLayout />
      <Toaster richColors position="top-right" />
    </>
  );
}

export default App;
