'use client';

import { useState, useEffect } from 'react';
import { supabase } from '@/lib/supabase';
import { useRouter, useParams } from 'next/navigation';
import { Letter } from '@/types';
import { Mail, ArrowLeft, Trash2, Save, Loader2, Globe, Calendar, Tag, CheckCircle2, Upload, FileText, X, Link as LinkIcon } from 'lucide-react';
import { COUNTRIES } from '@/constants/countries';
import { STATUSES } from '@/constants/statuses';

export default function EditLetterPage() {
  const { id } = useParams();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [letter, setLetter] = useState<Partial<Letter>>({});
  const [uploading, setUploading] = useState(false);
  const [sources, setSources] = useState<any[]>([]);
  const router = useRouter();

  useEffect(() => {
    async function fetchLetter() {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) {
        router.push('/login');
        return;
      }

      const { data, error } = await supabase
        .from('letters')
        .select('*')
        .eq('id', id)
        .single();

      if (error) {
        console.error('Error fetching letter:', error.message || error);
        router.push('/');
      } else {
        setLetter(data);
      }
      
      // Fetch sources for the user
      const { data: sourcesData, error: sourcesError } = await supabase
        .from('sources')
        .select('*')
        .eq('user_id', session.user.id)
        .order('name', { ascending: true });
      
      if (!sourcesError && sourcesData) {
        setSources(sourcesData);
      }

      setLoading(false);
    }

    if (id) fetchLetter();
  }, [id, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);

    const { error } = await supabase
      .from('letters')
      .update({
        name: letter.name,
        nickname: letter.nickname,
        to_country: letter.to_country,
        to_city: letter.to_city,
        to_zip_code: letter.to_zip_code,
        to_address_line1: letter.to_address_line1,
        to_address_line2: letter.to_address_line2,
        from_country: letter.from_country,
        from_city: letter.from_city,
        from_zip_code: letter.from_zip_code,
        from_address_line1: letter.from_address_line1,
        from_address_line2: letter.from_address_line2,
        letter_type: letter.letter_type,
        direction: letter.letter_type === 'Sending' ? 'sending' : 'receiving',
        sent_date: letter.sent_date,
        received_date: letter.received_date,
        tracking: letter.tracking,
        status: letter.status,
        attachment_url: letter.attachment_url,
        source_id: letter.source_id,
        is_completed: letter.is_completed,
      })
      .eq('id', id);

    if (error) {
      alert(error.message);
      setSaving(false);
    } else {
      router.push('/');
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    try {
      setUploading(true);
      if (!e.target.files || e.target.files.length === 0) return;

      const file = e.target.files[0];
      const fileExt = file.name.split('.').pop();
      const fileName = `${Math.random()}.${fileExt}`;
      const filePath = `${fileName}`;

      const { error: uploadError } = await supabase.storage
        .from('letter-attachments')
        .upload(filePath, file);

      if (uploadError) throw uploadError;

      const { data: { publicUrl } } = supabase.storage
        .from('letter-attachments')
        .getPublicUrl(filePath);

      setLetter({ ...letter, attachment_url: publicUrl });
    } catch (error: any) {
      alert('Error uploading file: ' + error.message);
    } finally {
      setUploading(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm('Are you sure you want to delete this letter?')) return;
    
    const { error } = await supabase
      .from('letters')
      .delete()
      .eq('id', id);

    if (error) {
      alert(error.message);
    } else {
      router.push('/');
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-brand-600"></div>
        <p className="mt-4 text-slate-500 font-medium">Loading letter details...</p>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="mb-8 flex items-center justify-between">
        <button
          onClick={() => router.back()}
          className="group flex items-center text-slate-500 hover:text-slate-900 transition-colors"
        >
          <ArrowLeft size={20} className="mr-2 group-hover:-translate-x-1 transition-transform" />
          <span className="font-medium">Back to dashboard</span>
        </button>
        
        <button
          onClick={handleDelete}
          className="flex items-center gap-2 text-red-500 hover:text-red-700 font-semibold transition-colors px-3 py-1.5 rounded-lg hover:bg-red-50"
        >
          <Trash2 size={18} />
          <span>Delete</span>
        </button>
      </div>

      <div className="flex items-center gap-4 mb-8">
        <div className="bg-brand-600 p-3 rounded-2xl text-white shadow-lg shadow-brand-600/20">
          <Mail size={28} />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-slate-900 tracking-tight">Edit Letter</h1>
          <p className="text-slate-500">Update the status or details of your letter</p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6 pb-12">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Basic Info & Direction */}
          <div className="lg:col-span-1 space-y-6">
            <div className="card p-6 h-full">
              <h3 className="text-lg font-bold text-slate-900 mb-6 flex items-center gap-2">
                <Tag size={18} className="text-brand-600" />
                Basic Info
              </h3>
              
              <div className="space-y-4">
                <div>
                  <label htmlFor="name" className="label-base">Name</label>
                  <input
                    id="name"
                    type="text"
                    required
                    className="w-full input-base"
                    value={letter.name || ''}
                    onChange={(e) => setLetter({ ...letter, name: e.target.value })}
                  />
                </div>
                <div>
                  <label htmlFor="nickname" className="label-base">Nickname (Optional)</label>
                  <input
                    id="nickname"
                    type="text"
                    className="w-full input-base"
                    value={letter.nickname || ''}
                    onChange={(e) => setLetter({ ...letter, nickname: e.target.value })}
                  />
                </div>
                <div className="pt-4 border-t border-slate-100">
                  <label htmlFor="letterType" className="label-base text-brand-700 font-bold">Direction</label>
                  <select
                    id="letterType"
                    className="w-full input-base border-brand-200 focus:border-brand-500 focus:ring-brand-500"
                    value={letter.letter_type || 'Sending'}
                    onChange={(e) => setLetter({ ...letter, letter_type: e.target.value as 'Sending' | 'Receiving' })}
                  >
                    <option value="Sending">Sending</option>
                    <option value="Receiving">Receiving</option>
                  </select>
                </div>
              </div>
            </div>
          </div>

          {/* Middle Column: Logistics & Address */}
          <div className="lg:col-span-2 space-y-6">
            <div className="card p-6">
              <h3 className="text-lg font-bold text-slate-900 mb-6 flex items-center gap-2">
                <Globe size={18} className="text-brand-600" />
                Logistics & Address
              </h3>
              
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-start mb-6">
                  {/* My Address */}
                  <div className="space-y-4">
                    <div className="h-6 flex items-center">
                      <label className="label-base font-semibold mb-0">My Address</label>
                    </div>
                    <div className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-600">
                      {letter.letter_type === 'Sending' ? letter.from_country : letter.to_country} {letter.from_city || letter.to_city ? `- ${letter.letter_type === 'Sending' ? letter.from_city : letter.to_city}` : ''}
                    </div>
                    <p className="text-xs text-slate-500 italic">This is your saved address used for this letter.</p>
                  </div>

                  {/* Other Side Address - Country */}
                  <div className="space-y-4">
                    <div className="h-6 flex items-center">
                      <label htmlFor="country" className="label-base font-semibold mb-0">
                        {letter.letter_type === 'Receiving' ? 'Sender Country' : 'Recipient Country'}
                      </label>
                    </div>
                    <select
                      id="country"
                      required
                      className="w-full input-base"
                      value={(letter.letter_type === 'Receiving' ? letter.from_country : letter.to_country) || ''}
                      onChange={(e) => {
                        if (letter.letter_type === 'Receiving') {
                          setLetter({ ...letter, from_country: e.target.value });
                        } else {
                          setLetter({ ...letter, to_country: e.target.value });
                        }
                      }}
                    >
                      <option value="">Select country</option>
                      {COUNTRIES.map(country => (
                        <option key={`country-${country}`} value={country}>{country}</option>
                      ))}
                    </select>
                    <p className="text-xs text-slate-500 italic">Choose the country for the {letter.letter_type === 'Receiving' ? 'sender' : 'recipient'}.</p>
                  </div>
                </div>

                <div className="pt-6 border-t border-slate-100">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-start mb-6">
                    {/* Source Selection */}
                    <div className="space-y-4">
                      <div className="h-6 flex items-center">
                        <label htmlFor="source" className="label-base font-semibold mb-0">Purchase Source (Optional)</label>
                      </div>
                      <select
                        id="source"
                        className="w-full input-base"
                        value={letter.source_id || ''}
                        onChange={(e) => setLetter({ ...letter, source_id: e.target.value ? parseInt(e.target.value) : undefined })}
                      >
                        <option value="">Select source</option>
                        {sources.map(source => (
                          <option key={source.id} value={source.id}>
                            {source.name}
                          </option>
                        ))}
                      </select>
                      <p className="text-xs text-slate-500 italic">e.g. eBay, Amazon, LastSticker</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-start">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label htmlFor="city" className="label-base">City</label>
                        <input
                          id="city"
                          type="text"
                          placeholder="City"
                          className="w-full input-base"
                          value={(letter.letter_type === 'Receiving' ? letter.from_city : letter.to_city) || ''}
                          onChange={(e) => {
                            if (letter.letter_type === 'Receiving') {
                              setLetter({ ...letter, from_city: e.target.value });
                            } else {
                              setLetter({ ...letter, to_city: e.target.value });
                            }
                          }}
                        />
                      </div>
                      <div>
                        <label htmlFor="zipCode" className="label-base">Zip Code</label>
                        <input
                          id="zipCode"
                          type="text"
                          placeholder="Zip Code"
                          className="w-full input-base"
                          value={(letter.letter_type === 'Receiving' ? letter.from_zip_code : letter.to_zip_code) || ''}
                          onChange={(e) => {
                            if (letter.letter_type === 'Receiving') {
                              setLetter({ ...letter, from_zip_code: e.target.value });
                            } else {
                              setLetter({ ...letter, to_zip_code: e.target.value });
                            }
                          }}
                        />
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div>
                        <label htmlFor="addressLine1" className="label-base">Address Line 1</label>
                        <input
                          id="addressLine1"
                          type="text"
                          placeholder="Street address, P.O. box"
                          className="w-full input-base"
                          value={(letter.letter_type === 'Receiving' ? letter.from_address_line1 : letter.to_address_line1) || ''}
                          onChange={(e) => {
                            if (letter.letter_type === 'Receiving') {
                              setLetter({ ...letter, from_address_line1: e.target.value });
                            } else {
                              setLetter({ ...letter, to_address_line1: e.target.value });
                            }
                          }}
                        />
                      </div>
                      <div>
                        <label htmlFor="addressLine2" className="label-base">Address Line 2 (Optional)</label>
                        <input
                          id="addressLine2"
                          type="text"
                          placeholder="Apartment, suite, etc."
                          className="w-full input-base"
                          value={(letter.letter_type === 'Receiving' ? letter.from_address_line2 : letter.to_address_line2) || ''}
                          onChange={(e) => {
                            if (letter.letter_type === 'Receiving') {
                              setLetter({ ...letter, from_address_line2: e.target.value });
                            } else {
                              setLetter({ ...letter, to_address_line2: e.target.value });
                            }
                          }}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom row: Attachment and Status */}
          <div className="lg:col-span-1 space-y-6">
            <div className="card p-6 h-full">
              <h3 className="text-lg font-bold text-slate-900 mb-6 flex items-center gap-2">
                <FileText size={18} className="text-brand-600" />
                Attachment
              </h3>
              
              <div className="space-y-4">
                {letter.attachment_url ? (
                  <div className="flex flex-col gap-3 p-4 bg-slate-50 border border-slate-200 rounded-xl">
                    <div className="flex items-center gap-3 overflow-hidden">
                      <FileText size={20} className="text-brand-600 shrink-0" />
                      <a 
                        href={letter.attachment_url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-sm font-medium text-brand-600 hover:text-brand-700 truncate underline decoration-brand-200 underline-offset-4"
                      >
                        View Attachment
                      </a>
                    </div>
                    <button
                      type="button"
                      onClick={() => setLetter({ ...letter, attachment_url: '' })}
                      className="flex items-center justify-center gap-2 w-full py-1.5 px-3 text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded-lg transition-colors"
                    >
                      <X size={14} />
                      Remove
                    </button>
                  </div>
                ) : (
                  <label className="flex flex-col items-center justify-center p-6 border-2 border-dashed border-slate-200 rounded-2xl hover:border-brand-500 hover:bg-brand-50/50 transition-all cursor-pointer group">
                    <div className="bg-slate-100 p-3 rounded-full group-hover:bg-brand-100 transition-colors">
                      {uploading ? (
                        <Loader2 size={24} className="text-brand-600 animate-spin" />
                      ) : (
                        <Upload size={24} className="text-slate-500 group-hover:text-brand-600" />
                      )}
                    </div>
                    <div className="mt-3 text-center">
                      <p className="text-sm font-semibold text-slate-900">
                        {uploading ? 'Uploading...' : 'Upload file'}
                      </p>
                    </div>
                    <input
                      type="file"
                      className="hidden"
                      onChange={handleFileUpload}
                      disabled={uploading}
                      accept=".pdf,.jpg,.jpeg,.png"
                    />
                  </label>
                )}
              </div>
            </div>
          </div>

          <div className="lg:col-span-2 space-y-6">
            <div className="card p-6">
              <h3 className="text-lg font-bold text-slate-900 mb-6 flex items-center gap-2">
                <CheckCircle2 size={18} className="text-brand-600" />
                Status & Timeline
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <div>
                  <label htmlFor="sentDate" className="label-base">Sent Date</label>
                  <input
                    id="sentDate"
                    type="date"
                    className="w-full input-base"
                    value={letter.sent_date || ''}
                    onChange={(e) => setLetter({ ...letter, sent_date: e.target.value })}
                  />
                </div>
                <div>
                  <label htmlFor="receivedDate" className="label-base">Received Date</label>
                  <input
                    id="receivedDate"
                    type="date"
                    className="w-full input-base"
                    value={letter.received_date || ''}
                    onChange={(e) => setLetter({ ...letter, received_date: e.target.value })}
                  />
                </div>
                <div>
                  <label htmlFor="status" className="label-base">Current Status</label>
                  <select
                    id="status"
                    className="w-full input-base"
                    value={letter.status || ''}
                    onChange={(e) => {
                      const newStatus = e.target.value;
                      const isDelivered = newStatus === 'Delivered';
                      
                      // Check if we can actually mark as Delivered
                      if (isDelivered && (!letter.sent_date || !letter.received_date)) {
                        alert('Both Sent and Received dates are required to mark as Delivered/Completed.');
                        return;
                      }

                      setLetter({ 
                        ...letter, 
                        status: newStatus,
                        is_completed: isDelivered ? true : letter.is_completed,
                        received_date: isDelivered && !letter.received_date 
                          ? new Date().toISOString().split('T')[0] 
                          : letter.received_date
                      });
                    }}
                  >
                    <option value="">Select status</option>
                    {STATUSES.map(s => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>
                <div className="md:col-span-2 lg:col-span-3">
                  <label htmlFor="tracking" className="label-base">Tracking Number</label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                      <Tag size={16} />
                    </div>
                    <input
                      id="tracking"
                      type="text"
                      placeholder="e.g. RR123456789CN"
                      className="pl-11 w-full input-base"
                      value={letter.tracking || ''}
                      onChange={(e) => setLetter({ ...letter, tracking: e.target.value })}
                    />
                  </div>
                </div>

                <div className="md:col-span-2 lg:col-span-3 pt-2">
                  <label className={`flex items-center p-4 rounded-xl border transition-all cursor-pointer ${
                    (!letter.sent_date || !letter.received_date) 
                      ? 'bg-slate-50 border-slate-100 opacity-60 cursor-not-allowed' 
                      : 'bg-brand-50/30 border-brand-100 hover:bg-brand-50/50'
                  }`}>
                    <div className="relative flex items-center">
                      <input
                        type="checkbox"
                        className="w-5 h-5 rounded border-slate-300 text-brand-600 focus:ring-brand-500 transition-all cursor-pointer disabled:cursor-not-allowed"
                        checked={letter.is_completed || false}
                        disabled={!letter.sent_date || !letter.received_date}
                        onChange={(e) => setLetter({ 
                          ...letter, 
                          is_completed: e.target.checked,
                          status: e.target.checked ? 'Delivered' : (letter.status === 'Delivered' ? 'Active' : letter.status)
                        })}
                      />
                    </div>
                    <div className="ml-3">
                      <span className={`text-sm font-bold ${(!letter.sent_date || !letter.received_date) ? 'text-slate-400' : 'text-slate-900'}`}>
                        Mark as Completed
                      </span>
                      <p className="text-xs text-slate-500 mt-0.5">
                        {(!letter.sent_date || !letter.received_date) 
                          ? 'Requires both sent and received dates' 
                          : 'Move this letter to the archive'}
                      </p>
                    </div>
                  </label>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-4 pt-4">
          <button
            type="button"
            onClick={() => router.back()}
            className="btn-secondary"
          >
            Cancel
          </button>
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
    </div>
  );
}
