'use client';

import { useState, useEffect } from 'react';
import { supabase } from '@/lib/supabase';
import { useRouter } from 'next/navigation';
import { Letter } from '@/types';
import { Shield, Mail, Search, Filter, Loader2, ArrowLeft, User as UserIcon, Calendar, MapPin, Tag, Edit2, Trash2, Users, FileText, Plus, X, Check, Settings, Upload, Globe, Image as ImageIcon } from 'lucide-react';

export default function AdminPage() {
  const [activeTab, setActiveTab] = useState<'letters' | 'users' | 'settings'>('letters');
  const [letters, setLetters] = useState<any[]>([]);
  const [profiles, setProfiles] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  
  // Settings state
  const [settings, setSettings] = useState<any>({
    logo_url: null,
    favicon_url: null,
    footer_text: ''
  });
  const [isSavingSettings, setIsSavingSettings] = useState(false);
  const [isUploadingLogo, setIsUploadingLogo] = useState(false);
  const [isUploadingFavicon, setIsUploadingFavicon] = useState(false);
  
  // Edit modals state
  const [isEditLetterModalOpen, setIsEditLetterModalOpen] = useState(false);
  const [selectedLetter, setSelectedLetter] = useState<any>(null);
  const [isEditUserModalOpen, setIsEditUserModalOpen] = useState(false);
  const [selectedProfile, setSelectedProfile] = useState<any>(null);
  const [isAddUserModalOpen, setIsAddUserModalOpen] = useState(false);
  const [newUser, setNewUser] = useState({ name: '', email: '', password: '', is_admin: false });
  const [isAddingUser, setIsAddingUser] = useState(false);
  
  const router = useRouter();

  useEffect(() => {
    async function checkAdminAndFetchData() {
      const { data: { session } } = await supabase.auth.getSession();
      
      if (!session) {
        router.push('/login');
        return;
      }

      // Check if user is admin
      const { data: profile, error: profileError } = await supabase
        .from('profiles')
        .select('is_admin')
        .eq('id', session.user.id)
        .single();

      if (profileError || !profile?.is_admin) {
        console.error('Not authorized');
        router.push('/dashboard');
        return;
      }

      setIsAdmin(true);
      await fetchData();
    }
    
    checkAdminAndFetchData();
  }, [router]);

  async function fetchData() {
    setLoading(true);
    // Fetch all letters
    const { data: lettersData, error: lettersError } = await supabase
      .from('letters')
      .select(`
        *,
        profiles:user_id (name, email)
      `)
      .order('created_at', { ascending: false });

    if (lettersError) {
      console.error('Error fetching letters:', lettersError.message);
    } else {
      setLetters(lettersData || []);
    }

    // Fetch all profiles
    const { data: profilesData, error: profilesError } = await supabase
      .from('profiles')
      .select('*')
      .order('created_at', { ascending: false });

    if (profilesError) {
      console.error('Error fetching profiles:', profilesError.message);
    } else {
      setProfiles(profilesData || []);
    }

    // Fetch settings
    const { data: settingsData, error: settingsError } = await supabase
      .from('settings')
      .select('*')
      .eq('id', 'global')
      .single();

    if (settingsError) {
      console.error('Error fetching settings:', settingsError.message);
    } else if (settingsData) {
      setSettings(settingsData);
    }

    setLoading(false);
  }

  const handleDeleteLetter = async (id: number) => {
    if (!confirm('Are you sure you want to delete this letter?')) return;
    
    const { error } = await supabase
      .from('letters')
      .delete()
      .eq('id', id);
      
    if (error) {
      alert('Error deleting letter: ' + error.message);
    } else {
      setLetters(letters.filter(l => l.id !== id));
    }
  };

  const handleDeleteProfile = async (id: string) => {
    if (!confirm('Are you sure you want to delete this user profile? This will NOT delete their Auth account but will remove their profile and potentially break their dashboard.')) return;
    
    const { error } = await supabase
      .from('profiles')
      .delete()
      .eq('id', id);
      
    if (error) {
      alert('Error deleting profile: ' + error.message);
    } else {
      setProfiles(profiles.filter(p => p.id !== id));
    }
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProfile) return;

    const { error } = await supabase
      .from('profiles')
      .update({
        name: selectedProfile.name,
        email: selectedProfile.email,
        is_admin: selectedProfile.is_admin
      })
      .eq('id', selectedProfile.id);

    if (error) {
      alert('Error updating profile: ' + error.message);
    } else {
      setProfiles(profiles.map(p => p.id === selectedProfile.id ? selectedProfile : p));
      setIsEditUserModalOpen(false);
    }
  };

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsAddingUser(true);

    try {
      // Step 1: Create user in Supabase Auth
      // Note: We are using the public signUp method. 
      // This will create a user and potentially log us out or send an email.
      // In a real production app, an admin would use the Admin Auth API (supabase.auth.admin.createUser)
      // but that requires the service_role key which shouldn't be exposed on the frontend.
      const { data: authData, error: authError } = await supabase.auth.signUp({
        email: newUser.email,
        password: newUser.password,
        options: {
          data: {
            full_name: newUser.name,
          }
        }
      });

      if (authError) throw authError;

      if (authData.user) {
        // Step 2: Update the profile if it was created by the trigger
        // Wait a bit for the trigger to finish
        await new Promise(resolve => setTimeout(resolve, 1000));

        if (newUser.is_admin) {
          const { error: profileError } = await supabase
            .from('profiles')
            .update({ is_admin: true })
            .eq('id', authData.user.id);
          
          if (profileError) console.error('Error setting admin status:', profileError);
        }

        alert('User created successfully! They will need to confirm their email if email confirmation is enabled.');
        setIsAddUserModalOpen(false);
        setNewUser({ name: '', email: '', password: '', is_admin: false });
        await fetchData(); // Refresh list
      }
    } catch (error: any) {
      alert('Error adding user: ' + error.message);
    } finally {
      setIsAddingUser(false);
    }
  };

  const handleUpdateSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingSettings(true);

    const { error } = await supabase
      .from('settings')
      .update({
        footer_text: settings.footer_text,
        updated_at: new Date().toISOString()
      })
      .eq('id', 'global');

    if (error) {
      alert('Error updating settings: ' + error.message);
    } else {
      alert('Settings updated successfully!');
    }
    setIsSavingSettings(false);
  };

  const uploadAsset = async (file: File, type: 'logo' | 'favicon') => {
    if (type === 'logo') setIsUploadingLogo(true);
    else setIsUploadingFavicon(true);

    try {
      const fileExt = file.name.split('.').pop();
      const fileName = `${type}-${Math.random()}.${fileExt}`;
      const filePath = `${fileName}`;

      const { error: uploadError } = await supabase.storage
        .from('site-assets')
        .upload(filePath, file);

      if (uploadError) throw uploadError;

      const { data: { publicUrl } } = supabase.storage
        .from('site-assets')
        .getPublicUrl(filePath);

      const updateData: any = {};
      if (type === 'logo') updateData.logo_url = publicUrl;
      else updateData.favicon_url = publicUrl;

      const { error: updateError } = await supabase
        .from('settings')
        .update(updateData)
        .eq('id', 'global');

      if (updateError) throw updateError;

      setSettings({ ...settings, ...updateData });
      alert(`${type.charAt(0).toUpperCase() + type.slice(1)} uploaded successfully!`);
    } catch (error: any) {
      alert(`Error uploading ${type}: ` + error.message);
    } finally {
      if (type === 'logo') setIsUploadingLogo(false);
      else setIsUploadingFavicon(false);
    }
  };

  const filteredLetters = letters.filter(letter => 
    letter.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    letter.profiles?.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    letter.profiles?.email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    letter.tracking?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredProfiles = profiles.filter(profile => 
    profile.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    profile.email?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-brand-600"></div>
        <p className="mt-4 text-slate-500 font-medium">Loading admin panel...</p>
      </div>
    );
  }

  if (!isAdmin) return null;

  return (
    <div className="max-w-7xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 pb-20">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-3xl font-bold text-slate-900 tracking-tight">Admin Control Panel</h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-brand-100 text-brand-700 uppercase tracking-wider flex items-center gap-1">
              <Shield size={12} />
              Admin
            </span>
          </div>
          <p className="text-slate-500">Manage all system correspondence and users</p>
        </div>
        <div className="flex items-center gap-3">
          {activeTab === 'users' && (
            <button
              onClick={() => setIsAddUserModalOpen(true)}
              className="flex items-center gap-2 px-4 py-2 bg-brand-600 text-white rounded-xl font-bold hover:bg-brand-700 transition-all shadow-lg shadow-brand-200"
            >
              <Plus size={18} />
              Add User
            </button>
          )}
          {activeTab !== 'settings' && (
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                <Search size={18} />
              </div>
              <input
                type="text"
                placeholder={`Search ${activeTab}...`}
                className="pl-10 pr-4 py-2 border border-slate-200 rounded-xl focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none w-full md:w-64 transition-all"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card p-6 border-l-4 border-brand-500">
          <div className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-1">Total Letters</div>
          <div className="text-3xl font-black text-slate-900">{letters.length}</div>
        </div>
        <div className="card p-6 border-l-4 border-emerald-500">
          <div className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-1">Active Users</div>
          <div className="text-3xl font-black text-slate-900">
            {profiles.length}
          </div>
        </div>
        <div className="card p-6 border-l-4 border-amber-500">
          <div className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-1">Completed</div>
          <div className="text-3xl font-black text-slate-900">
            {letters.filter(l => l.is_completed).length}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200">
        <button
          onClick={() => setActiveTab('letters')}
          className={`px-6 py-3 font-bold text-sm transition-all relative ${
            activeTab === 'letters' 
              ? 'text-brand-600' 
              : 'text-slate-400 hover:text-slate-600'
          }`}
        >
          <div className="flex items-center gap-2">
            <FileText size={18} />
            Letters
          </div>
          {activeTab === 'letters' && (
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-brand-500 rounded-t-full" />
          )}
        </button>
        <button
          onClick={() => setActiveTab('users')}
          className={`px-6 py-3 font-bold text-sm transition-all relative ${
            activeTab === 'users' 
              ? 'text-brand-600' 
              : 'text-slate-400 hover:text-slate-600'
          }`}
        >
          <div className="flex items-center gap-2">
            <Users size={18} />
            Users
          </div>
          {activeTab === 'users' && (
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-brand-500 rounded-t-full" />
          )}
        </button>
        <button
          onClick={() => setActiveTab('settings')}
          className={`px-6 py-3 font-bold text-sm transition-all relative ${
            activeTab === 'settings' 
              ? 'text-brand-600' 
              : 'text-slate-400 hover:text-slate-600'
          }`}
        >
          <div className="flex items-center gap-2">
            <Settings size={18} />
            Settings
          </div>
          {activeTab === 'settings' && (
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-brand-500 rounded-t-full" />
          )}
        </button>
      </div>

      {activeTab === 'letters' ? (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-100">
                  <th className="px-6 py-4 text-sm font-bold text-slate-600 uppercase tracking-wider">User</th>
                  <th className="px-6 py-4 text-sm font-bold text-slate-600 uppercase tracking-wider">Letter Details</th>
                  <th className="px-6 py-4 text-sm font-bold text-slate-600 uppercase tracking-wider">Route</th>
                  <th className="px-6 py-4 text-sm font-bold text-slate-600 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-4 text-sm font-bold text-slate-600 uppercase tracking-wider text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredLetters.map((letter) => (
                  <tr key={letter.id} className="hover:bg-slate-50/50 transition-colors">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="h-10 w-10 rounded-full bg-slate-100 flex items-center justify-center text-slate-500">
                          <UserIcon size={20} />
                        </div>
                        <div>
                          <div className="font-bold text-slate-900">{letter.profiles?.name || 'Unknown'}</div>
                          <div className="text-xs text-slate-500">{letter.profiles?.email}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="font-semibold text-slate-800">{letter.name}</div>
                      {letter.nickname && <div className="text-xs text-slate-500">"{letter.nickname}"</div>}
                      {letter.tracking && (
                        <div className="mt-1 inline-flex items-center gap-1 text-[10px] font-bold bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded uppercase">
                          <Tag size={10} />
                          {letter.tracking}
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2 text-sm">
                        <span className="font-medium text-slate-600">{letter.from_country}</span>
                        <ArrowLeft size={14} className={letter.letter_type === 'Sending' ? 'rotate-180 text-emerald-500' : 'text-amber-500'} />
                        <span className="font-medium text-slate-600">{letter.to_country}</span>
                      </div>
                      <div className="text-[10px] font-bold text-slate-400 uppercase mt-1">
                        {letter.letter_type}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                        letter.is_completed 
                          ? 'bg-emerald-100 text-emerald-700' 
                          : letter.status === 'Active' 
                          ? 'bg-blue-100 text-blue-700'
                          : 'bg-slate-100 text-slate-600'
                      }`}>
                        {letter.status || (letter.is_completed ? 'Completed' : 'Draft')}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => router.push(`/edit/${letter.id}`)}
                          className="p-2 text-slate-400 hover:text-brand-600 transition-colors"
                          title="Edit Letter"
                        >
                          <Edit2 size={18} />
                        </button>
                        <button
                          onClick={() => handleDeleteLetter(letter.id)}
                          className="p-2 text-slate-400 hover:text-rose-600 transition-colors"
                          title="Delete Letter"
                        >
                          <Trash2 size={18} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filteredLetters.length === 0 && (
            <div className="p-12 text-center text-slate-500">
              No letters found matching your search.
            </div>
          )}
        </div>
      ) : activeTab === 'users' ? (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-100">
                  <th className="px-6 py-4 text-sm font-bold text-slate-600 uppercase tracking-wider">User</th>
                  <th className="px-6 py-4 text-sm font-bold text-slate-600 uppercase tracking-wider">Admin Status</th>
                  <th className="px-6 py-4 text-sm font-bold text-slate-600 uppercase tracking-wider">Joined</th>
                  <th className="px-6 py-4 text-sm font-bold text-slate-600 uppercase tracking-wider text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredProfiles.map((profile) => (
                  <tr key={profile.id} className="hover:bg-slate-50/50 transition-colors">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="h-10 w-10 rounded-full bg-slate-100 flex items-center justify-center text-slate-500">
                          <UserIcon size={20} />
                        </div>
                        <div>
                          <div className="font-bold text-slate-900">{profile.name || 'No Name'}</div>
                          <div className="text-xs text-slate-500">{profile.email}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      {profile.is_admin ? (
                        <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-brand-100 text-brand-700 uppercase tracking-wider flex items-center gap-1 w-fit">
                          <Shield size={12} />
                          Admin
                        </span>
                      ) : (
                        <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-slate-100 text-slate-600 uppercase tracking-wider w-fit block">
                          User
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm text-slate-600">
                        {new Date(profile.created_at).toLocaleDateString()}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => {
                            setSelectedProfile(profile);
                            setIsEditUserModalOpen(true);
                          }}
                          className="p-2 text-slate-400 hover:text-brand-600 transition-colors"
                          title="Edit User"
                        >
                          <Edit2 size={18} />
                        </button>
                        <button
                          onClick={() => handleDeleteProfile(profile.id)}
                          className="p-2 text-slate-400 hover:text-rose-600 transition-colors"
                          title="Delete User"
                        >
                          <Trash2 size={18} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filteredProfiles.length === 0 && (
            <div className="p-12 text-center text-slate-500">
              No users found matching your search.
            </div>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="card p-8">
            <h2 className="text-xl font-bold text-slate-900 mb-6 flex items-center gap-2">
              <Globe size={20} className="text-brand-500" />
              Site Identity
            </h2>
            
            <div className="space-y-8">
              {/* Logo Upload */}
              <div>
                <label className="block text-sm font-bold text-slate-700 mb-3">Site Logo</label>
                <div className="flex items-center gap-6">
                  <div className="h-24 w-24 rounded-xl border-2 border-dashed border-slate-200 bg-slate-50 flex items-center justify-center overflow-hidden">
                    {settings.logo_url ? (
                      <img src={settings.logo_url} alt="Logo" className="max-h-full max-w-full object-contain" />
                    ) : (
                      <ImageIcon className="text-slate-300" size={32} />
                    )}
                  </div>
                  <div className="flex-1">
                    <p className="text-sm text-slate-500 mb-3">Upload your custom logo. Transparent PNG or SVG recommended.</p>
                    <label className="inline-flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-lg font-bold text-slate-700 hover:bg-slate-50 cursor-pointer transition-all shadow-sm">
                      {isUploadingLogo ? (
                        <Loader2 size={18} className="animate-spin text-brand-500" />
                      ) : (
                        <Upload size={18} className="text-brand-500" />
                      )}
                      <span>{isUploadingLogo ? 'Uploading...' : 'Upload Logo'}</span>
                      <input 
                        type="file" 
                        className="hidden" 
                        accept="image/*"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (file) uploadAsset(file, 'logo');
                        }}
                        disabled={isUploadingLogo}
                      />
                    </label>
                  </div>
                </div>
              </div>

              {/* Favicon Upload */}
              <div>
                <label className="block text-sm font-bold text-slate-700 mb-3">Favicon</label>
                <div className="flex items-center gap-6">
                  <div className="h-16 w-16 rounded-xl border-2 border-dashed border-slate-200 bg-slate-50 flex items-center justify-center overflow-hidden">
                    {settings.favicon_url ? (
                      <img src={settings.favicon_url} alt="Favicon" className="h-8 w-8 object-contain" />
                    ) : (
                      <Globe className="text-slate-300" size={24} />
                    )}
                  </div>
                  <div className="flex-1">
                    <p className="text-sm text-slate-500 mb-3">Upload a favicon (32x32 or 16x16 .ico or .png).</p>
                    <label className="inline-flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-lg font-bold text-slate-700 hover:bg-slate-50 cursor-pointer transition-all shadow-sm">
                      {isUploadingFavicon ? (
                        <Loader2 size={18} className="animate-spin text-brand-500" />
                      ) : (
                        <Upload size={18} className="text-brand-500" />
                      )}
                      <span>{isUploadingFavicon ? 'Uploading...' : 'Upload Favicon'}</span>
                      <input 
                        type="file" 
                        className="hidden" 
                        accept="image/*"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (file) uploadAsset(file, 'favicon');
                        }}
                        disabled={isUploadingFavicon}
                      />
                    </label>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="card p-8">
            <h2 className="text-xl font-bold text-slate-900 mb-6 flex items-center gap-2">
              <FileText size={20} className="text-brand-500" />
              Footer & Content
            </h2>
            
            <form onSubmit={handleUpdateSettings} className="space-y-6">
              <div>
                <label className="block text-sm font-bold text-slate-700 mb-2">Footer Copyright Line</label>
                <textarea
                  className="w-full px-4 py-3 border border-slate-200 rounded-xl focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition-all min-h-[100px]"
                  placeholder="e.g. © 2024 Letter Tracker. All rights reserved."
                  value={settings.footer_text}
                  onChange={(e) => setSettings({ ...settings, footer_text: e.target.value })}
                />
              </div>

              <div className="pt-4">
                <button
                  type="submit"
                  disabled={isSavingSettings}
                  className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-brand-600 text-white rounded-xl font-bold hover:bg-brand-700 transition-all shadow-lg shadow-brand-200 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isSavingSettings ? (
                    <>
                      <Loader2 size={20} className="animate-spin" />
                      Saving...
                    </>
                  ) : (
                    <>
                      <Check size={20} />
                      Save Settings
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add User Modal */}
      {isAddUserModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md overflow-hidden animate-in zoom-in-95 duration-200">
            <div className="p-6 border-b border-slate-100 flex items-center justify-between">
              <h3 className="text-xl font-bold text-slate-900">Add New User</h3>
              <button 
                onClick={() => setIsAddUserModalOpen(false)}
                className="p-2 text-slate-400 hover:text-slate-600 transition-colors"
              >
                <X size={20} />
              </button>
            </div>
            <form onSubmit={handleAddUser} className="p-6 space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Full Name</label>
                <input
                  type="text"
                  required
                  placeholder="John Doe"
                  className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition-all"
                  value={newUser.name}
                  onChange={(e) => setNewUser({...newUser, name: e.target.value})}
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Email Address</label>
                <input
                  type="email"
                  required
                  placeholder="john@example.com"
                  className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition-all"
                  value={newUser.email}
                  onChange={(e) => setNewUser({...newUser, email: e.target.value})}
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Password</label>
                <input
                  type="password"
                  required
                  minLength={6}
                  placeholder="••••••••"
                  className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition-all"
                  value={newUser.password}
                  onChange={(e) => setNewUser({...newUser, password: e.target.value})}
                />
              </div>
              <div className="flex items-center gap-3 p-4 bg-slate-50 rounded-xl">
                <input
                  type="checkbox"
                  id="addNewAdmin"
                  className="h-5 w-5 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                  checked={newUser.is_admin}
                  onChange={(e) => setNewUser({...newUser, is_admin: e.target.checked})}
                />
                <label htmlFor="addNewAdmin" className="flex items-center gap-2 cursor-pointer">
                  <Shield size={16} className={newUser.is_admin ? "text-brand-600" : "text-slate-400"} />
                  <span className="font-bold text-slate-700">Grant Admin Privileges</span>
                </label>
              </div>
              <div className="pt-4 flex gap-3">
                <button
                  type="button"
                  onClick={() => setIsAddUserModalOpen(false)}
                  className="flex-1 px-6 py-3 border border-slate-200 rounded-xl font-bold text-slate-600 hover:bg-slate-50 transition-all"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isAddingUser}
                  className="flex-1 px-6 py-3 bg-brand-600 text-white rounded-xl font-bold hover:bg-brand-700 shadow-lg shadow-brand-200 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {isAddingUser ? <Loader2 size={18} className="animate-spin" /> : <Plus size={18} />}
                  Create User
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit User Modal */}
      {isEditUserModalOpen && selectedProfile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md overflow-hidden animate-in zoom-in-95 duration-200">
            <div className="p-6 border-b border-slate-100 flex items-center justify-between">
              <h3 className="text-xl font-bold text-slate-900">Edit User Profile</h3>
              <button 
                onClick={() => setIsEditUserModalOpen(false)}
                className="p-2 text-slate-400 hover:text-slate-600 transition-colors"
              >
                <X size={20} />
              </button>
            </div>
            <form onSubmit={handleUpdateProfile} className="p-6 space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Full Name</label>
                <input
                  type="text"
                  required
                  className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition-all"
                  value={selectedProfile.name}
                  onChange={(e) => setSelectedProfile({...selectedProfile, name: e.target.value})}
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Email Address</label>
                <input
                  type="email"
                  required
                  className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-brand-500 focus:border-brand-500 outline-none transition-all"
                  value={selectedProfile.email}
                  onChange={(e) => setSelectedProfile({...selectedProfile, email: e.target.value})}
                />
              </div>
              <div className="flex items-center gap-3 p-4 bg-slate-50 rounded-xl">
                <input
                  type="checkbox"
                  id="isAdmin"
                  className="h-5 w-5 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                  checked={selectedProfile.is_admin}
                  onChange={(e) => setSelectedProfile({...selectedProfile, is_admin: e.target.checked})}
                />
                <label htmlFor="isAdmin" className="flex items-center gap-2 cursor-pointer">
                  <Shield size={16} className={selectedProfile.is_admin ? "text-brand-600" : "text-slate-400"} />
                  <span className="font-bold text-slate-700">Administrator Privileges</span>
                </label>
              </div>
              <div className="pt-4 flex gap-3">
                <button
                  type="button"
                  onClick={() => setIsEditUserModalOpen(false)}
                  className="flex-1 px-6 py-3 border border-slate-200 rounded-xl font-bold text-slate-600 hover:bg-slate-50 transition-all"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 px-6 py-3 bg-brand-600 text-white rounded-xl font-bold hover:bg-brand-700 shadow-lg shadow-brand-200 transition-all flex items-center justify-center gap-2"
                >
                  <Check size={18} />
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
