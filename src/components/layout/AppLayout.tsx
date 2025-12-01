import { Sidebar } from "./Sidebar";
import { MainContent } from "./MainContent";

export function AppLayout() {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background">
      <Sidebar />
      <MainContent />
    </div>
  );
}
