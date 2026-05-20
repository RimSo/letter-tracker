'use client';

import { useState, useEffect } from 'react';
import { supabase } from '@/lib/supabase';
import { useRouter } from 'next/navigation';
import { Globe, Users, Mail, Send, Inbox, Loader2, ArrowRight, TrendingUp } from 'lucide-react';
import Link from 'next/link';

export default function HomePage() {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<any>(null);
  const router = useRouter();

  useEffect(() => {
    async function fetchData() {
      // Check for session
      const { data: { session } } = await supabase.auth.getSession();
      setUser(session?.user ?? null);

      const { data, error } = await supabase
        .rpc('get_global_stats');

      if (error) {
        console.error('Error fetching global stats:', error.message || error);
      } else if (data && data.length > 0) {
        const statsData = data[0];
        
        // Transform JSONB objects to arrays for sorting if needed, though RPC already limits to 5
        const topSentTo = statsData.top_sent_to 
          ? Object.entries(statsData.top_sent_to).sort(([, a]: any, [, b]: any) => b - a)
          : [];
        const topReceivedFrom = statsData.top_received_from 
          ? Object.entries(statsData.top_received_from).sort(([, a]: any, [, b]: any) => b - a)
          : [];

        setStats({ 
          total: statsData.total_letters, 
          sending: statsData.sending_count, 
          receiving: statsData.receiving_count, 
          uniqueUsers: statsData.total_users,
          topSentTo,
          topReceivedFrom
        });
      }
      setLoading(false);
    }
    fetchData();
  }, [router]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-brand-600"></div>
        <p className="mt-4 text-slate-500 font-medium">Fetching global community data...</p>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="text-center space-y-4">
        <div className="inline-flex items-center justify-center p-3 bg-brand-50 text-brand-600 rounded-2xl mb-2">
          <Globe size={32} />
        </div>
        <h1 className="text-4xl font-extrabold text-slate-900 tracking-tight">Global Statistics</h1>
        <p className="text-lg text-slate-500 max-w-2xl mx-auto">
          See how the community is using LetterTracker around the world.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        <GlobalStatCard 
          label="Letters Tracked" 
          value={stats.total} 
          icon={<Mail size={24} />}
          description="Total correspondence logged by all users"
        />
        <GlobalStatCard 
          label="Active Users" 
          value={stats.uniqueUsers} 
          icon={<Users size={24} />}
          description="Unique individuals tracking their mail"
        />
        <GlobalStatCard 
          label="Active Letters" 
          value={stats.sending + stats.receiving} 
          icon={<Send size={24} />}
          description="Total incoming and outgoing items"
        />
      </div>

      {!user && (
        <div className="flex justify-center">
          <Link 
            href="/login" 
            className="btn-primary py-4 px-10 text-lg rounded-2xl shadow-xl shadow-brand-200 flex items-center gap-3 group"
          >
            <span>Start Tracking Now</span>
            <ArrowRight className="group-hover:translate-x-1 transition-transform" />
          </Link>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="card p-8 space-y-6">
          <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <Globe size={20} className="text-brand-600" />
            Top Community Countries
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Top Destinations</h4>
              {stats.topSentTo && stats.topSentTo.length > 0 ? (
                <div className="space-y-2">
                  {stats.topSentTo.map(([country, count]: [string, number]) => (
                    <div key={country} className="flex justify-between items-center group">
                      <span className="text-slate-700 group-hover:text-brand-600 transition-colors font-medium">{country}</span>
                      <span className="bg-emerald-50 text-emerald-600 px-2 py-0.5 rounded-full text-xs font-bold">{count}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-400 text-sm italic">No data yet</p>
              )}
            </div>
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Top Origins</h4>
              {stats.topReceivedFrom && stats.topReceivedFrom.length > 0 ? (
                <div className="space-y-2">
                  {stats.topReceivedFrom.map(([country, count]: [string, number]) => (
                    <div key={country} className="flex justify-between items-center group">
                      <span className="text-slate-700 group-hover:text-brand-600 transition-colors font-medium">{country}</span>
                      <span className="bg-amber-50 text-amber-600 px-2 py-0.5 rounded-full text-xs font-bold">{count}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-400 text-sm italic">No data yet</p>
              )}
            </div>
          </div>
        </div>

        <div className="card bg-brand-900 text-white p-8 overflow-hidden relative flex flex-col justify-center">
          <div className="absolute top-0 right-0 -mt-8 -mr-8 opacity-10 rotate-12">
            <Globe size={240} />
          </div>
          <div className="relative z-10">
            <h3 className="text-xl font-bold mb-3 flex items-center gap-2">
              <TrendingUp size={20} className="text-brand-300" />
              Community Impact
            </h3>
            <p className="text-brand-100 text-md leading-relaxed mb-6">
              Every letter tracked is a story shared. From Qatar to the rest of the world, 
              we're helping people stay connected, one stamp at a time.
            </p>
            <div className="flex gap-8">
              <div>
                <div className="text-2xl font-black text-white">{stats.sending}</div>
                <div className="text-brand-300 text-xs font-bold uppercase tracking-wider">Total Sent</div>
              </div>
              <div>
                <div className="text-2xl font-black text-white">{stats.receiving}</div>
                <div className="text-brand-300 text-xs font-bold uppercase tracking-wider">Total Received</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function GlobalStatCard({ label, value, icon, description }: { label: string, value: number, icon: React.ReactNode, description: string }) {
  return (
    <div className="card p-8 flex flex-col items-center text-center space-y-4 hover:border-brand-300 transition-colors group">
      <div className="p-4 rounded-2xl bg-slate-50 text-brand-600 group-hover:bg-brand-600 group-hover:text-white transition-all duration-300">
        {icon}
      </div>
      <div>
        <div className="text-4xl font-black text-slate-900 mb-1">{value.toLocaleString()}</div>
        <div className="text-sm font-bold text-slate-400 uppercase tracking-widest">{label}</div>
      </div>
      <p className="text-slate-500 text-sm">{description}</p>
    </div>
  );
}
