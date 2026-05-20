'use client';

import { useState, useEffect } from 'react';
import { supabase } from '@/lib/supabase';
import { useRouter } from 'next/navigation';
import { Mail, ArrowLeft, Send, Save, Loader2, Globe, Calendar, Tag, MapPin, CheckCircle2, Upload, FileText, X, Link as LinkIcon } from 'lucide-react';
import { COUNTRIES } from '@/constants/countries';
import { STATUSES } from '@/constants/statuses';

export default function AddLetterPage() {
  const [name, setName] = useState('');
  const [nickname, setNickname] = useState('');
  const [toCountry, setToCountry] = useState('');
  const [toCity, setToCity] = useState('');
  const [toZipCode, setToZipCode] = useState('');
  const [toAddressLine1, setToAddressLine1] = useState('');
  const [toAddressLine2, setToAddressLine2] = useState('');
  
  const [fromCountry, setFromCountry] = useState('Qatar');
  const [fromCity, setFromCity] = useState('');
  const [fromZipCode, setFromZipCode] = useState('');
  const [fromAddressLine1, setFromAddressLine1] = useState('');
  const [fromAddressLine2, setFromAddressLine2] = useState('');
  const [letterType, setLetterType] = useState<'Sending' | 'Receiving'>('Sending');
  const [sentDate, setSentDate] = useState('');
  const [tracking, setTracking] = useState('');
  const [attachmentUrl, setAttachmentUrl] = useState('');
  const [uploading, setUploading] = useState(false);
  const [loading, setLoading] = useState(false);
  const [addresses, setAddresses] = useState<any[]>([]);
  const [selectedAddressId, setSelectedAddressId] = useState<string>('');
  const [sources, setSources] = useState<any[]>([]);
  const [selectedSourceId, setSelectedSourceId] = useState<string>('');
  const router = useRouter();

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (!session) {
        router.push('/login');
      } else {
        fetchAddresses(session.user.id);
        fetchSources(session.user.id);
      }
    });
  }, [router]);

  const fetchAddresses = async (userId: string) => {
    const { data, error } = await supabase
      .from('addresses')
      .select('*')
      .eq('user_id', userId)
      .order('is_default', { ascending: false });

    if (!error && data) {
      setAddresses(data);
      // If there's a default address, pre-select it and set the country
      const defaultAddress = data.find(a => a.is_default);
      if (defaultAddress) {
        setSelectedAddressId(defaultAddress.id.toString());
        updateAddressFieldsFromAddress(defaultAddress, letterType);
      }
    }
  };

  const updateAddressFieldsFromAddress = (address: any, type: string) => {
    if (type === 'Sending') {
      setFromCountry(address.country || '');
      setFromCity(address.city || '');
      setFromZipCode(address.zip_code || '');
      // If the address has a full_address, we might need to split it or just put it in line 1
      setFromAddressLine1(address.full_address || '');
      setFromAddressLine2('');
    } else {
      setToCountry(address.country || '');
      setToCity(address.city || '');
      setToZipCode(address.zip_code || '');
      setToAddressLine1(address.full_address || '');
      setToAddressLine2('');
    }
  };

  const handleAddressChange = (addressId: string) => {
    setSelectedAddressId(addressId);
    if (addressId) {
      const address = addresses.find(a => a.id.toString() === addressId);
      if (address) {
        updateAddressFieldsFromAddress(address, letterType);
      }
    }
  };

  const fetchSources = async (userId: string) => {
    const { data, error } = await supabase
      .from('sources')
      .select('*')
      .eq('user_id', userId)
      .order('name', { ascending: true });

    if (!error && data) {
      setSources(data);
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

      setAttachmentUrl(publicUrl);
    } catch (error: any) {
      alert('Error uploading file: ' + error.message);
    } finally {
      setUploading(false);
    }
  };

  const handleCountryChange = (val: string) => {
    if (letterType === 'Sending') {
      setToCountry(val);
    } else {
      setFromCountry(val);
    }
  };

  const handleDirectionChange = (newType: 'Sending' | 'Receiving') => {
    setLetterType(newType);
    
    // Clear the fields that will now be manually selected
    if (newType === 'Sending') {
      setToCountry('');
      setToCity('');
      setToZipCode('');
      setToAddressLine1('');
      setToAddressLine2('');
    } else {
      setFromCountry('');
      setFromCity('');
      setFromZipCode('');
      setFromAddressLine1('');
      setFromAddressLine2('');
    }

    // If an address is selected, re-apply it to the correct field
    if (selectedAddressId) {
      const address = addresses.find(a => a.id.toString() === selectedAddressId);
      if (address) {
        updateAddressFieldsFromAddress(address, newType);
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;

    const currentStatus = sentDate ? 'Active' : 'Draft';

    // Create the first letter
    const { error: firstError } = await supabase.from('letters').insert({
      user_id: session.user.id,
      name,
      nickname,
      to_country: toCountry,
      to_city: toCity,
      to_zip_code: toZipCode,
      to_address_line1: toAddressLine1,
      to_address_line2: toAddressLine2,
      from_country: fromCountry,
      from_city: fromCity,
      from_zip_code: fromZipCode,
      from_address_line1: fromAddressLine1,
      from_address_line2: fromAddressLine2,
      letter_type: letterType,
      direction: letterType === 'Sending' ? 'sending' : 'receiving',
      sent_date: sentDate || null,
      tracking,
      status: currentStatus,
      attachment_url: attachmentUrl || null,
      source_id: selectedSourceId ? parseInt(selectedSourceId) : null,
      is_completed: false,
    });

    if (firstError) {
      alert(firstError.message);
      setLoading(false);
      return;
    }

    // Create the opposite draft letter
    const { error: secondError } = await supabase.from('letters').insert({
      user_id: session.user.id,
      name,
      nickname,
      to_country: fromCountry,
      to_city: fromCity,
      to_zip_code: fromZipCode,
      to_address_line1: fromAddressLine1,
      to_address_line2: fromAddressLine2,
      from_country: toCountry,
      from_city: toCity,
      from_zip_code: toZipCode,
      from_address_line1: toAddressLine1,
      from_address_line2: toAddressLine2,
      letter_type: letterType === 'Sending' ? 'Receiving' : 'Sending',
      direction: letterType === 'Sending' ? 'receiving' : 'sending',
      sent_date: null,
      tracking: '',
      status: 'Draft',
      attachment_url: attachmentUrl || null,
      source_id: selectedSourceId ? parseInt(selectedSourceId) : null,
      is_completed: false,
    });

    if (secondError) {
      console.error('Error creating opposite draft:', secondError.message);
      // We don't necessarily want to block the whole flow if the draft fails, 
      // but maybe alert the user or just proceed.
    }

    router.push('/');
  };

  return (
    <div className="max-w-5xl mx-auto animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="mb-8 flex items-center justify-between">
        <button
          onClick={() => router.back()}
          className="group flex items-center text-slate-500 hover:text-slate-900 transition-colors"
        >
          <ArrowLeft size={20} className="mr-2 group-hover:-translate-x-1 transition-transform" />
          <span className="font-medium">Back to letters</span>
        </button>
      </div>

      <div className="flex items-center gap-4 mb-8">
        <div className="bg-brand-600 p-3 rounded-2xl text-white shadow-lg shadow-brand-600/20">
          <Mail size={28} />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-slate-900 tracking-tight">Add New Letter</h1>
          <p className="text-slate-500">Enter the details of your correspondence</p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
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
                    placeholder="Recipient/Sender Name"
                    className="w-full input-base"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </div>
                <div>
                  <label htmlFor="nickname" className="label-base">Nickname (Optional)</label>
                  <input
                    id="nickname"
                    type="text"
                    placeholder="Nickname"
                    className="w-full input-base"
                    value={nickname}
                    onChange={(e) => setNickname(e.target.value)}
                  />
                </div>
                <div className="pt-4 border-t border-slate-100">
                  <label htmlFor="letterType" className="label-base text-brand-700 font-bold">Direction</label>
                  <select
                    id="letterType"
                    className="w-full input-base border-brand-200 focus:border-brand-500 focus:ring-brand-500"
                    value={letterType}
                    onChange={(e) => handleDirectionChange(e.target.value as 'Sending' | 'Receiving')}
                  >
                    <option value="Sending">I am sending this</option>
                    <option value="Receiving">I am receiving this</option>
                  </select>
                </div>
              </div>
            </div>
          </div>

          {/* Middle Column: Addresses */}
          <div className="lg:col-span-2 space-y-6">
            <div className="card p-6">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                  <MapPin size={18} className="text-brand-600" />
                  Logistics & Address
                </h3>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-start mb-6">
                {/* My Address Selection */}
                <div className="space-y-4">
                  <div className="h-6 flex items-center">
                    <label htmlFor="myAddress" className="label-base font-semibold mb-0">My Address</label>
                  </div>
                  <select
                    id="myAddress"
                    className="w-full input-base bg-slate-50"
                    value={selectedAddressId}
                    onChange={(e) => handleAddressChange(e.target.value)}
                  >
                    <option value="">Select one of my addresses</option>
                    {addresses.map(addr => (
                      <option key={addr.id} value={addr.id}>
                        {addr.title} ({addr.country})
                      </option>
                    ))}
                  </select>
                  <p className="text-xs text-slate-500 italic">This address will be used as the "{letterType === 'Sending' ? 'From' : 'To'}" field.</p>
                </div>

                {/* Other Side Address - Country */}
                <div className="space-y-4">
                  <div className="h-6 flex items-center">
                    <label htmlFor="toCountry" className="label-base font-semibold mb-0">
                      {letterType === 'Sending' ? 'Recipient Country' : 'Sender Country'}
                    </label>
                  </div>
                  <select
                    id="toCountry"
                    required
                    className="w-full input-base"
                    value={letterType === 'Sending' ? toCountry : fromCountry}
                    onChange={(e) => handleCountryChange(e.target.value)}
                  >
                    <option value="">Select country</option>
                    {COUNTRIES.map(country => (
                      <option key={`country-${country}`} value={country}>{country}</option>
                    ))}
                  </select>
                  <p className="text-xs text-slate-500 italic">Choose the country for the {letterType === 'Sending' ? 'recipient' : 'sender'}.</p>
                </div>
              </div>

              <div className="pt-6 border-t border-slate-100">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-start mb-6">
                  {/* Source Selection */}
                  <div className="space-y-4">
                    <div className="h-6 flex items-center">
                      <label htmlFor="source" className="label-base font-semibold mb-0">Purchase Source (Optional)</label>
                    </div>
                    <div className="flex gap-2">
                      <select
                        id="source"
                        className="w-full input-base"
                        value={selectedSourceId}
                        onChange={(e) => setSelectedSourceId(e.target.value)}
                      >
                        <option value="">Select source</option>
                        {sources.map(source => (
                          <option key={source.id} value={source.id}>
                            {source.name}
                          </option>
                        ))}
                      </select>
                    </div>
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
                        value={letterType === 'Sending' ? toCity : fromCity}
                        onChange={(e) => {
                          if (letterType === 'Sending') {
                            setToCity(e.target.value);
                          } else {
                            setFromCity(e.target.value);
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
                        value={letterType === 'Sending' ? toZipCode : fromZipCode}
                        onChange={(e) => {
                          if (letterType === 'Sending') {
                            setToZipCode(e.target.value);
                          } else {
                            setFromZipCode(e.target.value);
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
                        value={letterType === 'Sending' ? toAddressLine1 : fromAddressLine1}
                        onChange={(e) => {
                          if (letterType === 'Sending') {
                            setToAddressLine1(e.target.value);
                          } else {
                            setFromAddressLine1(e.target.value);
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
                        value={letterType === 'Sending' ? toAddressLine2 : fromAddressLine2}
                        onChange={(e) => {
                          if (letterType === 'Sending') {
                            setToAddressLine2(e.target.value);
                          } else {
                            setFromAddressLine2(e.target.value);
                          }
                        }}
                      />
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
                {attachmentUrl ? (
                  <div className="flex items-center justify-between p-4 bg-slate-50 border border-slate-200 rounded-xl">
                    <div className="flex items-center gap-3 overflow-hidden">
                      <FileText size={20} className="text-brand-600 shrink-0" />
                      <span className="text-sm font-medium text-slate-700 truncate">
                        {attachmentUrl.split('/').pop()}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => setAttachmentUrl('')}
                      className="p-1 hover:bg-slate-200 rounded-full transition-colors text-slate-500"
                    >
                      <X size={18} />
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
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label htmlFor="sentDate" className="label-base">Sent Date</label>
                  <input
                    id="sentDate"
                    type="date"
                    className="w-full input-base"
                    value={sentDate}
                    onChange={(e) => setSentDate(e.target.value)}
                  />
                </div>
                <div>
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
                      value={tracking}
                      onChange={(e) => setTracking(e.target.value)}
                    />
                  </div>
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
            disabled={loading}
            className="btn-primary min-w-[160px] flex justify-center items-center gap-2"
          >
            {loading ? (
              <Loader2 className="animate-spin" size={20} />
            ) : (
              <>
                <Save size={20} />
                <span>Add Letter</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
