'use client';

import { useState, useEffect } from 'react';
import { supabase } from '@/lib/supabase';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import { Mail, LayoutDashboard, BarChart3, Globe, User, LogOut, Menu, X, Shield } from 'lucide-react';

export default function Navbar() {
  const [user, setUser] = useState<any>(null);
  const [profile, setProfile] = useState<any>(null);
  const [settings, setSettings] = useState<any>(null);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    async function getSession() {
      const { data: { session } } = await supabase.auth.getSession();
      setUser(session?.user ?? null);
      if (session?.user) {
        fetchProfile(session.user.id);
      }
    }

    async function fetchSettings() {
      const { data } = await supabase
        .from('settings')
        .select('*')
        .eq('id', 'global')
        .single();
      if (data) setSettings(data);
    }

    getSession();
    fetchSettings();

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
      if (session?.user) {
        fetchProfile(session.user.id);
      } else {
        setProfile(null);
      }
    });

    return () => subscription.unsubscribe();
  }, []);

  const fetchProfile = async (userId: string) => {
    const { data } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', userId)
      .single();
    setProfile(data);
  };

  const handleLogout = async () => {
    await supabase.auth.signOut();
    router.push('/login');
    setIsMenuOpen(false);
    setIsProfileOpen(false);
  };

  const navItems = [
    { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
    { name: 'My Stats', href: '/stats', icon: BarChart3 },
    { name: 'Global Stats', href: '/', icon: Globe },
  ];

  if (profile?.is_admin) {
    // We only want Admin in the dropdown, not the main nav anymore
    // navItems.push({ name: 'Admin', href: '/admin', icon: Shield });
  }

  const guestNavItems = [
    { name: 'Global Stats', href: '/', icon: Globe },
  ];

  const isActive = (path: string) => pathname === path;

  return (
    <nav className="bg-white/80 backdrop-blur-md sticky top-0 z-50 border-b border-slate-200/60">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex items-center">
            <Link href="/" className="flex items-center gap-2 group">
              {settings?.logo_url ? (
                <div className="h-8 w-auto flex items-center">
                  <img src={settings.logo_url} alt="Logo" className="h-full object-contain" />
                </div>
              ) : (
                <>
                  <div className="bg-brand-600 p-1.5 rounded-lg text-white group-hover:rotate-12 transition-transform duration-300">
                    <Mail size={20} />
                  </div>
                  <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-brand-600 to-brand-800">
                    LetterTracker
                  </span>
                </>
              )}
            </Link>

            <div className="hidden md:ml-10 md:flex md:space-x-4">
              {(user ? navItems : guestNavItems).map((item) => (
                <Link
                  key={item.name}
                  href={item.href}
                  className={`inline-flex items-center px-3 py-2 text-sm font-medium rounded-xl transition-colors duration-200 ${
                    isActive(item.href)
                      ? 'bg-brand-50 text-brand-700'
                      : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                  }`}
                >
                  <item.icon className="mr-2 h-4 w-4" />
                  {item.name}
                </Link>
              ))}
            </div>
          </div>

          <div className="flex items-center">
            {user ? (
              <div className="hidden md:flex items-center space-x-3 relative">
                <button
                  onClick={() => setIsProfileOpen(!isProfileOpen)}
                  className={`flex items-center gap-2 p-1.5 rounded-xl transition-all duration-200 ${
                    isProfileOpen || isActive('/profile') 
                      ? 'bg-brand-50 text-brand-700' 
                      : 'text-slate-600 hover:bg-slate-50'
                  }`}
                  title="Profile menu"
                >
                  <div className="h-8 w-8 rounded-lg bg-brand-100 flex items-center justify-center text-brand-700 font-bold border border-brand-200 overflow-hidden">
                    {profile?.avatar_url ? (
                      <img src={profile.avatar_url} alt={profile.name || ''} className="h-full w-full object-cover" />
                    ) : (
                      profile?.name?.[0]?.toUpperCase() || profile?.email?.[0]?.toUpperCase() || <User size={18} />
                    )}
                  </div>
                </button>

                {isProfileOpen && (
                  <>
                    <div 
                      className="fixed inset-0 z-10" 
                      onClick={() => setIsProfileOpen(false)}
                    ></div>
                    <div className="absolute right-0 top-full mt-2 w-56 rounded-2xl bg-white border border-slate-200 shadow-xl shadow-slate-200/50 py-2 z-20 animate-in fade-in zoom-in-95 duration-200 origin-top-right">
                      <div className="px-4 py-3 border-b border-slate-100 mb-1">
                        <p className="text-sm font-bold text-slate-900 truncate">{profile?.name || 'User'}</p>
                        <p className="text-xs text-slate-500 truncate">{profile?.email}</p>
                      </div>
                      
                      <Link
                        href="/profile"
                        onClick={() => setIsProfileOpen(false)}
                        className={`flex items-center px-4 py-2.5 text-sm font-medium transition-colors ${
                          isActive('/profile') 
                            ? 'text-brand-700 bg-brand-50/50' 
                            : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                        }`}
                      >
                        <User size={16} className="mr-3 text-slate-400" />
                        My Profile
                      </Link>

                      {profile?.is_admin && (
                        <Link
                          href="/admin"
                          onClick={() => setIsProfileOpen(false)}
                          className={`flex items-center px-4 py-2.5 text-sm font-medium transition-colors ${
                            isActive('/admin') 
                              ? 'text-brand-700 bg-brand-50/50' 
                              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                          }`}
                        >
                          <Shield size={16} className="mr-3 text-slate-400" />
                          Admin Panel
                        </Link>
                      )}

                      <div className="mt-1 pt-1 border-t border-slate-100">
                        <button
                          onClick={handleLogout}
                          className="flex items-center w-full px-4 py-2.5 text-sm font-medium text-red-600 hover:bg-red-50 transition-colors"
                        >
                          <LogOut size={16} className="mr-3" />
                          Logout
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="hidden md:flex items-center space-x-3">
                <Link 
                  href="/login" 
                  className="px-4 py-2 text-sm font-semibold text-slate-700 hover:text-slate-900 transition-colors"
                >
                  Sign in
                </Link>
                <Link 
                  href="/register" 
                  className="btn-primary py-2 px-5 text-sm"
                >
                  Get started
                </Link>
              </div>
            )}

            {/* Mobile menu button */}
            <div className="flex md:hidden">
                <button
                  onClick={() => setIsMenuOpen(!isMenuOpen)}
                  className="inline-flex items-center justify-center p-2 rounded-xl text-slate-600 hover:bg-slate-100 focus:outline-none"
                >
                  {isMenuOpen ? (
                    <X size={24} />
                  ) : user ? (
                    <div className="h-8 w-8 rounded-lg bg-brand-100 flex items-center justify-center text-brand-700 font-bold border border-brand-200 overflow-hidden">
                      {profile?.avatar_url ? (
                        <img src={profile.avatar_url} alt={profile.name || ''} className="h-full w-full object-cover" />
                      ) : (
                        profile?.name?.[0]?.toUpperCase() || profile?.email?.[0]?.toUpperCase() || <User size={18} />
                      )}
                    </div>
                  ) : (
                    <Menu size={24} />
                  )}
                </button>
            </div>
          </div>
        </div>
      </div>

      {/* Mobile menu */}
      {isMenuOpen && (
        <div className="md:hidden bg-white border-b border-slate-200 px-4 pt-2 pb-6 space-y-2">
          {(user ? navItems : guestNavItems).map((item) => (
            <Link
              key={item.name}
              href={item.href}
              onClick={() => setIsMenuOpen(false)}
              className={`flex items-center px-4 py-3 rounded-xl text-base font-medium ${
                isActive(item.href)
                  ? 'bg-brand-50 text-brand-700'
                  : 'text-slate-600 hover:bg-slate-50'
              }`}
            >
              <item.icon className="mr-3 h-5 w-5" />
              {item.name}
            </Link>
          ))}
          {user ? (
            <>
              <div className="pt-4 mt-4 border-t border-slate-100 space-y-2">
                <Link
                  href="/profile"
                  onClick={() => setIsMenuOpen(false)}
                  className={`flex items-center px-4 py-3 rounded-xl text-base font-medium ${
                    isActive('/profile') ? 'bg-brand-50 text-brand-700' : 'text-slate-600'
                  }`}
                >
                  <User size={20} className="mr-3" /> Profile
                </Link>
                {profile?.is_admin && (
                  <Link
                    href="/admin"
                    onClick={() => setIsMenuOpen(false)}
                    className={`flex items-center px-4 py-3 rounded-xl text-base font-medium ${
                      isActive('/admin') ? 'bg-brand-50 text-brand-700' : 'text-slate-600'
                    }`}
                  >
                    <Shield size={20} className="mr-3" /> Admin Panel
                  </Link>
                )}
                <button
                  onClick={handleLogout}
                  className="flex items-center w-full px-4 py-3 rounded-xl text-base font-medium text-red-600 hover:bg-red-50"
                >
                  <LogOut size={20} className="mr-3" /> Logout
                </button>
              </div>
            </>
          ) : (
            <div className="flex flex-col space-y-3 pt-2">
              <Link
                href="/login"
                onClick={() => setIsMenuOpen(false)}
                className="w-full text-center px-4 py-3 rounded-xl text-slate-700 font-semibold bg-slate-100"
              >
                Sign in
              </Link>
              <Link
                href="/register"
                onClick={() => setIsMenuOpen(false)}
                className="btn-primary w-full text-center"
              >
                Get started
              </Link>
            </div>
          )}
        </div>
      )}
    </nav>
  );
}
