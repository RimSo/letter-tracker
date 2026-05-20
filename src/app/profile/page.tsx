'use client';

import { useState, useEffect, useRef } from 'react';
import { supabase } from '@/lib/supabase';
import { useRouter } from 'next/navigation';
import { Profile, Address, Source } from '@/types';
import { User, Mail, Calendar, Save, Loader2, ArrowLeft, Camera, ShieldCheck, MapPin, Plus, Trash2, Edit2, X, Check, Globe, Link as LinkIcon, ExternalLink } from 'lucide-react';
import { COUNTRIES } from '@/constants/countries';

export default function ProfilePage() {
  const [profile, setProfile] = useState<Partial<Profile>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [addresses, setAddresses] = useState<Address[]>([]);
  const [addressLoading, setAddressLoading] = useState(true);
  const [isAddingAddress, setIsAddingAddress] = useState(false);
  const [editingAddressId, setEditingAddressId] = useState<number | null>(null);
  const [newAddress, setNewAddress] = useState<Partial<Address>>({
    title: '',
    full_address: '',
    country: 'Qatar',
    city: '',
    zip_code: '',
    is_default: false
  });
  const [sources, setSources] = useState<Source[]>([]);
  const [sourcesLoading, setSourcesLoading] = useState(true);
  const [isAddingSource, setIsAddingSource] = useState(false);
  const [editingSourceId, setEditingSourceId] = useState<number | null>(null);
  const [newSource, setNewSource] = useState<Partial<Source>>({
    name: '',
    link: ''
  });
  const router = useRouter();

  useEffect(() => {
    async function fetchProfile() {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) {
        router.push('/login');
        return;
      }

      const { data, error } = await supabase
        .from('profiles')
        .select('*')
        .eq('id', session.user.id)
        .single();

      if (error) {
        console.error('Error fetching profile:', error.message || error);
      } else {
        setProfile(data);
      }
      setLoading(false);
    }

    async function fetchAddresses() {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) return;

      const { data, error } = await supabase
        .from('addresses')
        .select('*')
        .order('is_default', { ascending: false })
        .order('created_at', { ascending: false });

      if (error) {
        console.error('Error fetching addresses:', error.message || error);
      } else {
        setAddresses(data || []);
      }
      setAddressLoading(false);
    }

    async function fetchSources() {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) return;

      const { data, error } = await supabase
        .from('sources')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) {
        console.error('Error fetching sources:', error.message || error);
      } else {
        setSources(data || []);
      }
      setSourcesLoading(false);
    }

    fetchProfile();
    fetchAddresses();
    fetchSources();
  }, [router]);
  
  const uploadAvatar = async (event: React.ChangeEvent<HTMLInputElement>) => {
    try {
      setUploading(true);

      if (!event.target.files || event.target.files.length === 0) {
        throw new Error('You must select an image to upload.');
      }

      const { data: { session } } = await supabase.auth.getSession();
      if (!session) throw new Error('No session');

      const file = event.target.files[0];
      const fileExt = file.name.split('.').pop();
      const filePath = `${session.user.id}/${Math.random()}.${fileExt}`;

      const { error: uploadError } = await supabase.storage
        .from('avatars')
        .upload(filePath, file);

      if (uploadError) {
        throw uploadError;
      }

      const { data: { publicUrl } } = supabase.storage
        .from('avatars')
        .getPublicUrl(filePath);

      const { error: updateError } = await supabase
        .from('profiles')
        .update({ avatar_url: publicUrl })
        .eq('id', session.user.id);

      if (updateError) {
        throw updateError;
      }

      setProfile({ ...profile, avatar_url: publicUrl });
      alert('Avatar updated successfully!');
    } catch (error: any) {
      alert(error.message);
    } finally {
      setUploading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);

    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;

    // If first_name or surname are empty, try to derive them from name
    let firstName = profile.first_name;
    let surname = profile.surname;

    if ((!firstName || !firstName.trim()) && profile.name) {
      const parts = profile.name.trim().split(/\s+/);
      if (parts.length > 0) {
        firstName = parts[0];
      }
    }

    if ((!surname || !surname.trim()) && profile.name) {
      const parts = profile.name.trim().split(/\s+/);
      if (parts.length > 1) {
        surname = parts.slice(1).join(' ');
      }
    }

    const { error } = await supabase
      .from('profiles')
      .update({
        name: profile.name,
        first_name: firstName,
        middle_name: profile.middle_name,
        surname: surname,
        gender: profile.gender,
        date_of_birth: profile.date_of_birth,
      })
      .eq('id', session.user.id);

    if (error) {
      alert(error.message);
    } else {
      setProfile({
        ...profile,
        first_name: firstName,
        surname: surname
      });
      alert('Profile updated successfully!');
    }
    setSaving(false);
  };

  const handleAddAddress = async (e: React.FormEvent) => {
    e.preventDefault();
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;

    if (editingAddressId) {
      const { error } = await supabase
        .from('addresses')
        .update({
          title: newAddress.title,
          full_address: newAddress.full_address,
          country: newAddress.country,
          city: newAddress.city,
          zip_code: newAddress.zip_code,
          is_default: newAddress.is_default
        })
        .eq('id', editingAddressId);

      if (error) {
        alert(error.message);
      } else {
        // If this address is set as default, unset others
        if (newAddress.is_default) {
          await supabase
            .from('addresses')
            .update({ is_default: false })
            .neq('id', editingAddressId)
            .eq('user_id', session.user.id);
        }
        resetAddressForm();
        fetchAddresses();
      }
    } else {
      const { data, error } = await supabase
        .from('addresses')
        .insert([{
          user_id: session.user.id,
          title: newAddress.title,
          full_address: newAddress.full_address,
          country: newAddress.country,
          city: newAddress.city,
          zip_code: newAddress.zip_code,
          is_default: newAddress.is_default
        }])
        .select();

      if (error) {
        alert(error.message);
      } else {
        // If this address is set as default, unset others
        if (newAddress.is_default && data?.[0]) {
          await supabase
            .from('addresses')
            .update({ is_default: false })
            .neq('id', data[0].id)
            .eq('user_id', session.user.id);
        }
        resetAddressForm();
        fetchAddresses();
      }
    }
  };

  const resetAddressForm = () => {
    setNewAddress({
      title: '',
      full_address: '',
      country: 'Qatar',
      city: '',
      zip_code: '',
      is_default: false
    });
    setIsAddingAddress(false);
    setEditingAddressId(null);
  };

  const fetchSources = async () => {
    const { data, error } = await supabase
      .from('sources')
      .select('*')
      .order('created_at', { ascending: false });

    if (!error) {
      setSources(data || []);
    }
  };

  const handleAddSource = async (e: React.FormEvent) => {
    e.preventDefault();
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;

    if (editingSourceId) {
      const { error } = await supabase
        .from('sources')
        .update({
          name: newSource.name,
          link: newSource.link
        })
        .eq('id', editingSourceId);

      if (error) {
        alert(error.message);
      } else {
        resetSourceForm();
        fetchSources();
      }
    } else {
      const { error } = await supabase
        .from('sources')
        .insert([{
          user_id: session.user.id,
          name: newSource.name,
          link: newSource.link
        }]);

      if (error) {
        alert(error.message);
      } else {
        resetSourceForm();
        fetchSources();
      }
    }
  };

  const resetSourceForm = () => {
    setNewSource({
      name: '',
      link: ''
    });
    setIsAddingSource(false);
    setEditingSourceId(null);
  };

  const handleEditSource = (source: Source) => {
    setNewSource({
      name: source.name,
      link: source.link
    });
    setEditingSourceId(source.id);
    setIsAddingSource(true);
  };

  const handleDeleteSource = async (id: number) => {
    if (!confirm('Are you sure you want to delete this source?')) return;

    const { error } = await supabase
      .from('sources')
      .delete()
      .eq('id', id);

    if (error) {
      alert(error.message);
    } else {
      fetchSources();
    }
  };

  const addDefaultSources = async () => {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;

    const defaultSources = [
      { user_id: session.user.id, name: 'eBay', link: 'https://www.ebay.com' },
      { user_id: session.user.id, name: 'Amazon', link: 'https://www.amazon.com' },
      { user_id: session.user.id, name: 'LastSticker', link: 'https://www.laststicker.com' }
    ];

    const { error } = await supabase
      .from('sources')
      .insert(defaultSources);

    if (error) {
      alert(error.message);
    } else {
      fetchSources();
    }
  };

  const fetchAddresses = async () => {
    const { data, error } = await supabase
      .from('addresses')
      .select('*')
      .order('is_default', { ascending: false })
      .order('created_at', { ascending: false });

    if (!error) {
      setAddresses(data || []);
    }
  };

  const handleEditAddress = (address: Address) => {
    setNewAddress({
      title: address.title,
      full_address: address.full_address,
      country: address.country,
      city: address.city,
      zip_code: address.zip_code,
      is_default: address.is_default
    });
    setEditingAddressId(address.id);
    setIsAddingAddress(true);
  };

  const handleDeleteAddress = async (id: number) => {
    if (!confirm('Are you sure you want to delete this address?')) return;

    const { error } = await supabase
      .from('addresses')
      .delete()
      .eq('id', id);

    if (error) {
      alert(error.message);
    } else {
      fetchAddresses();
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-brand-600"></div>
        <p className="mt-4 text-slate-500 font-medium">Loading your profile...</p>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 tracking-tight">Account Settings</h1>
          <p className="text-slate-500 mt-1">Manage your personal information</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="space-y-8">
          <div className="card p-6 flex flex-col items-center text-center">
            <div className="relative group">
              <div className="h-24 w-24 bg-brand-100 rounded-full flex items-center justify-center text-brand-600 mb-4 border-4 border-white shadow-sm overflow-hidden">
                {uploading ? (
                  <Loader2 className="animate-spin" size={32} />
                ) : profile.avatar_url ? (
                  <img src={profile.avatar_url} alt={profile.name || ''} className="h-full w-full object-cover" />
                ) : (
                  <User size={40} />
                )}
              </div>
              <input
                type="file"
                id="avatar"
                accept="image/*"
                onChange={uploadAvatar}
                disabled={uploading}
                ref={fileInputRef}
                className="hidden"
              />
              <button 
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
                className="absolute bottom-4 right-0 bg-white p-1.5 rounded-full shadow-md border border-slate-100 text-slate-500 hover:text-brand-600 transition-colors disabled:opacity-50"
              >
                <Camera size={16} />
              </button>
            </div>
            <h2 className="text-xl font-bold text-slate-900">{profile.name}</h2>
            <p className="text-slate-500 text-sm mb-6">{profile.email}</p>
            
            <div className="w-full pt-6 border-t border-slate-100 space-y-3">
              <div className="flex items-center gap-3 text-sm text-slate-600">
                <ShieldCheck size={18} className="text-emerald-500" />
                <span>Verified Account</span>
              </div>
              <div className="flex items-center gap-3 text-sm text-slate-600">
                <Calendar size={18} className="text-brand-500" />
                <span>Joined {new Date(profile.created_at || '').toLocaleDateString('en-US', { month: 'long', year: 'numeric' })}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2">
          <form onSubmit={handleSubmit} className="space-y-8">
            <div className="card p-8 space-y-8">
              <div className="space-y-6">
                <h3 className="text-lg font-bold text-slate-900 pb-2 border-b border-slate-100">Display Information</h3>
                <div className="space-y-1">
                  <label htmlFor="name" className="label-base">Display Name</label>
                  <input
                    id="name"
                    type="text"
                    required
                    className="w-full input-base"
                    value={profile.name || ''}
                    onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                  />
                  <p className="text-xs text-slate-400">This is how your name will appear to other users.</p>
                </div>
              </div>

              <div className="space-y-6">
                <h3 className="text-lg font-bold text-slate-900 pb-2 border-b border-slate-100">Personal Details</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-1">
                    <label htmlFor="firstName" className="label-base">First Name</label>
                    <input
                      id="firstName"
                      type="text"
                      placeholder={profile.name?.split(' ')[0] || ''}
                      className="w-full input-base"
                      value={profile.first_name || ''}
                      onChange={(e) => setProfile({ ...profile, first_name: e.target.value })}
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="surname" className="label-base">Surname</label>
                    <input
                      id="surname"
                      type="text"
                      placeholder={profile.name?.split(' ').slice(1).join(' ') || ''}
                      className="w-full input-base"
                      value={profile.surname || ''}
                      onChange={(e) => setProfile({ ...profile, surname: e.target.value })}
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="gender" className="label-base">Gender</label>
                    <select
                      id="gender"
                      className="w-full input-base"
                      value={profile.gender || ''}
                      onChange={(e) => setProfile({ ...profile, gender: e.target.value })}
                    >
                      <option value="">Select Gender</option>
                      <option value="Male">Male</option>
                      <option value="Female">Female</option>
                      <option value="Other">Other</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <label htmlFor="dob" className="label-base">Date of Birth</label>
                    <input
                      id="dob"
                      type="date"
                      className="w-full input-base"
                      value={profile.date_of_birth || ''}
                      onChange={(e) => setProfile({ ...profile, date_of_birth: e.target.value })}
                    />
                  </div>
                </div>
              </div>
            </div>

            <div className="flex justify-end">
              <button
                type="submit"
                disabled={saving}
                className="btn-primary min-w-[160px] flex justify-center items-center gap-2"
              >
                {saving ? (
                  <Loader2 className="animate-spin" size={20} />
                ) : (
                  <>
                    <Save size={20} />
                    <span>Save Changes</span>
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Addresses Section */}
          <div className="mt-12 space-y-6">
            <div className="flex items-center justify-between">
              <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2">
                <MapPin className="text-brand-600" size={24} />
                My Addresses
              </h3>
              {!isAddingAddress && (
                <button 
                  onClick={() => setIsAddingAddress(true)}
                  className="btn-secondary py-2 flex items-center gap-2"
                >
                  <Plus size={18} />
                  <span>Add Address</span>
                </button>
              )}
            </div>

            {isAddingAddress && (
              <div className="card p-6 border-brand-200 bg-brand-50/30 animate-in fade-in zoom-in-95 duration-200">
                <form onSubmit={handleAddAddress} className="space-y-4">
                  <div className="flex justify-between items-center mb-4">
                    <h4 className="font-bold text-slate-900">{editingAddressId ? 'Edit Address' : 'New Address'}</h4>
                    <button 
                      type="button" 
                      onClick={resetAddressForm}
                      className="text-slate-400 hover:text-slate-600 transition-colors"
                    >
                      <X size={20} />
                    </button>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-1">
                      <label className="label-base">Address Title</label>
                      <input
                        type="text"
                        placeholder="e.g., Home, Work, Qatar Address"
                        required
                        className="w-full input-base"
                        value={newAddress.title || ''}
                        onChange={(e) => setNewAddress({ ...newAddress, title: e.target.value })}
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="label-base">Country</label>
                      <select
                        className="w-full input-base"
                        value={newAddress.country || 'Qatar'}
                        onChange={(e) => setNewAddress({ ...newAddress, country: e.target.value })}
                      >
                        {COUNTRIES.map(c => (
                          <option key={c} value={c}>{c}</option>
                        ))}
                      </select>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="label-base">Full Address</label>
                    <textarea
                      rows={2}
                      required
                      className="w-full input-base py-2"
                      placeholder="Street, Building, Apartment..."
                      value={newAddress.full_address || ''}
                      onChange={(e) => setNewAddress({ ...newAddress, full_address: e.target.value })}
                    />
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-1">
                      <label className="label-base">City (Optional)</label>
                      <input
                        type="text"
                        className="w-full input-base"
                        value={newAddress.city || ''}
                        onChange={(e) => setNewAddress({ ...newAddress, city: e.target.value })}
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="label-base">ZIP / Postal Code (Optional)</label>
                      <input
                        type="text"
                        className="w-full input-base"
                        value={newAddress.zip_code || ''}
                        onChange={(e) => setNewAddress({ ...newAddress, zip_code: e.target.value })}
                      />
                    </div>
                  </div>

                  <div className="flex items-center gap-2 pt-2">
                    <input
                      id="isDefault"
                      type="checkbox"
                      className="h-4 w-4 text-brand-600 border-slate-300 rounded focus:ring-brand-500"
                      checked={newAddress.is_default || false}
                      onChange={(e) => setNewAddress({ ...newAddress, is_default: e.target.checked })}
                    />
                    <label htmlFor="isDefault" className="text-sm font-medium text-slate-700">Set as default address</label>
                  </div>

                  <div className="flex justify-end gap-3 pt-4">
                    <button 
                      type="button" 
                      onClick={resetAddressForm}
                      className="btn-secondary py-2 px-4"
                    >
                      Cancel
                    </button>
                    <button 
                      type="submit" 
                      className="btn-primary py-2 px-6"
                    >
                      {editingAddressId ? 'Update Address' : 'Save Address'}
                    </button>
                  </div>
                </form>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {addressLoading ? (
                <div className="col-span-full py-12 flex flex-col items-center justify-center text-slate-400">
                  <Loader2 className="animate-spin mb-2" size={32} />
                  <p>Loading addresses...</p>
                </div>
              ) : addresses.length === 0 ? (
                <div className="col-span-full py-12 card border-dashed flex flex-col items-center justify-center text-slate-400 text-center">
                  <MapPin className="mb-3 opacity-20" size={48} />
                  <p className="font-medium">No addresses added yet</p>
                  <p className="text-sm">Add addresses to quickly use them for your letters</p>
                </div>
              ) : (
                addresses.map((addr) => (
                  <div key={addr.id} className={`card p-5 group relative transition-all duration-200 hover:shadow-md ${addr.is_default ? 'border-brand-300 bg-brand-50/10' : ''}`}>
                    <div className="flex justify-between items-start mb-3">
                      <div className="flex items-center gap-2">
                        <h4 className="font-bold text-slate-900">{addr.title}</h4>
                        {addr.is_default && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-brand-100 text-brand-700 uppercase tracking-wider">
                            Default
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button 
                          onClick={() => handleEditAddress(addr)}
                          className="p-1.5 text-slate-400 hover:text-brand-600 hover:bg-brand-50 rounded-lg transition-all"
                          title="Edit"
                        >
                          <Edit2 size={16} />
                        </button>
                        <button 
                          onClick={() => handleDeleteAddress(addr.id)}
                          className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-all"
                          title="Delete"
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </div>
                    
                    <div className="space-y-1.5">
                      <p className="text-sm text-slate-600 line-clamp-2">{addr.full_address}</p>
                      <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-slate-400">
                        <span className="flex items-center gap-1">
                          <Check size={12} className="text-brand-500" />
                          {addr.country}
                        </span>
                        {addr.city && <span>• {addr.city}</span>}
                        {addr.zip_code && <span>• {addr.zip_code}</span>}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="card p-8 space-y-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-purple-100 text-purple-600 rounded-lg">
                  <LinkIcon size={20} />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-slate-900">Purchase Sources</h3>
                  <p className="text-sm text-slate-500">Add platforms where your letters originate (e.g., eBay, Amazon)</p>
                </div>
              </div>
              <div className="flex gap-2">
                {sources.length === 0 && !sourcesLoading && (
                  <button 
                    onClick={addDefaultSources}
                    className="btn-secondary py-2 px-3 text-xs flex items-center gap-1.5"
                  >
                    <Plus size={14} /> Add Defaults
                  </button>
                )}
                <button 
                  onClick={() => setIsAddingSource(true)}
                  className="btn-primary py-2 px-4 text-sm flex items-center gap-2"
                >
                  <Plus size={18} /> Add Source
                </button>
              </div>
            </div>

            {isAddingSource && (
              <div className="p-6 bg-slate-50 rounded-xl border border-slate-200 animate-in fade-in zoom-in-95 duration-200">
                <form onSubmit={handleAddSource} className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-1">
                      <label className="label-base">Source Name</label>
                      <input
                        type="text"
                        required
                        className="w-full input-base"
                        placeholder="e.g. eBay, Amazon"
                        value={newSource.name || ''}
                        onChange={(e) => setNewSource({ ...newSource, name: e.target.value })}
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="label-base">Website Link (Optional)</label>
                      <input
                        type="url"
                        className="w-full input-base"
                        placeholder="https://..."
                        value={newSource.link || ''}
                        onChange={(e) => setNewSource({ ...newSource, link: e.target.value })}
                      />
                    </div>
                  </div>

                  <div className="flex justify-end gap-3 pt-2">
                    <button 
                      type="button" 
                      onClick={resetSourceForm}
                      className="btn-secondary py-2 px-4"
                    >
                      Cancel
                    </button>
                    <button 
                      type="submit" 
                      className="btn-primary py-2 px-6"
                    >
                      {editingSourceId ? 'Update Source' : 'Save Source'}
                    </button>
                  </div>
                </form>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {sourcesLoading ? (
                <div className="col-span-full py-8 flex flex-col items-center justify-center text-slate-400">
                  <Loader2 className="animate-spin mb-2" size={24} />
                  <p className="text-sm">Loading sources...</p>
                </div>
              ) : sources.length === 0 ? (
                <div className="col-span-full py-10 card border-dashed flex flex-col items-center justify-center text-slate-400 text-center">
                  <LinkIcon className="mb-2 opacity-20" size={32} />
                  <p className="font-medium text-sm">No sources added yet</p>
                </div>
              ) : (
                sources.map((source) => (
                  <div key={source.id} className="card p-4 group relative flex items-center justify-between hover:shadow-md transition-all">
                    <div className="flex flex-col min-w-0">
                      <h4 className="font-bold text-slate-900 truncate">{source.name}</h4>
                      {source.link && (
                        <a 
                          href={source.link} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-xs text-brand-600 flex items-center gap-1 hover:underline truncate"
                        >
                          <ExternalLink size={10} />
                          {new URL(source.link).hostname}
                        </a>
                      )}
                    </div>
                    <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button 
                        onClick={() => handleEditSource(source)}
                        className="p-1.5 text-slate-400 hover:text-brand-600 hover:bg-brand-50 rounded-lg transition-all"
                      >
                        <Edit2 size={14} />
                      </button>
                      <button 
                        onClick={() => handleDeleteSource(source.id)}
                        className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-all"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
