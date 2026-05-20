'use client';

import { useState, useEffect } from "react";
import { Inter } from "next/font/google";
import "./globals.css";
import Navbar from "@/components/layout/Navbar";
import { supabase } from "@/lib/supabase";

const inter = Inter({ subsets: ["latin"] });

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [settings, setSettings] = useState<any>(null);

  useEffect(() => {
    async function fetchSettings() {
      const { data } = await supabase
        .from('settings')
        .select('*')
        .eq('id', 'global')
        .single();
      if (data) setSettings(data);
    }
    fetchSettings();
  }, []);

  return (
    <html lang="en">
      <head>
        {settings?.favicon_url && <link rel="icon" href={settings.favicon_url} />}
        <title>{settings?.title || "Letter Tracker"}</title>
        <meta name="description" content={settings?.description || "Track your sent and received letters"} />
      </head>
      <body className={`${inter.className} min-h-screen flex flex-col`}>
        <Navbar />
        <main className="flex-grow max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8 w-full">
          {children}
        </main>
        <footer className="border-t border-slate-200 py-8 bg-white mt-auto">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <p className="text-center text-slate-500 text-sm font-medium">
              {settings?.footer_text || "© 2024 Letter Tracker. All rights reserved."}
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
