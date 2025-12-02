import { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { MainContent } from "./MainContent";

interface AppLayoutProps {
  children?: ReactNode;
}

export function AppLayout({ children }: AppLayoutProps) {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background pb-6">
      <Sidebar />
      {children ?? <MainContent />}
    </div>
  );
}
