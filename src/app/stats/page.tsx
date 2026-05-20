'use client';

import { useState, useEffect } from 'react';
import { supabase } from '@/lib/supabase';
import { useRouter } from 'next/navigation';
import { Letter } from '@/types';
import { BarChart3, Mail, Send, Inbox, CheckCircle2, TrendingUp, Globe } from 'lucide-react';

export default function StatsPage() {
  const [letters, setLetters] = useState<Letter[]>([]);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    async function fetchData() {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) {
        router.push('/login');
        return;
      }

      const { data, error } = await supabase
        .from('letters')
        .select('*');

      if (error) {
        console.error('Error fetching stats:', error.message || error);
      } else {
        setLetters(data || []);
      }
      setLoading(false);
    }
    fetchData();
  }, [router]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-brand-600"></div>
        <p className="mt-4 text-slate-500 font-medium">Calculating your stats...</p>
      </div>
    );
  }

  const total = letters.length;
  const sending = letters.filter(l => l.letter_type === 'Sending').length;
  const receiving = letters.filter(l => l.letter_type === 'Receiving').length;
  const completed = letters.filter(l => l.is_completed).length;

  // Calculate top countries
  const sentToCountries = letters
    .filter(l => l.letter_type === 'Sending' && l.to_country)
    .reduce((acc, l) => {
      acc[l.to_country] = (acc[l.to_country] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

  const receivedFromCountries = letters
    .filter(l => l.letter_type === 'Receiving' && l.from_country)
    .reduce((acc, l) => {
      acc[l.from_country] = (acc[l.from_country] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

  const topSentTo = Object.entries(sentToCountries)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);

  const topReceivedFrom = Object.entries(receivedFromCountries)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);

  return (
    <div className="max-w-5xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 tracking-tight">Your Statistics</h1>
          <p className="text-slate-500 mt-1">Overview of your letter tracking activity</p>
        </div>
        <div className="bg-brand-50 p-3 rounded-2xl text-brand-600">
          <BarChart3 size={28} />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard 
          label="Total Letters" 
          value={total} 
          icon={<Mail size={20} />}
          color="bg-blue-50 text-blue-600 border-blue-100"
        />
        <StatCard 
          label="Sending" 
          value={sending} 
          icon={<Send size={20} />}
          color="bg-emerald-50 text-emerald-600 border-emerald-100"
        />
        <StatCard 
          label="Receiving" 
          value={receiving} 
          icon={<Inbox size={20} />}
          color="bg-amber-50 text-amber-600 border-amber-100"
        />
        <StatCard 
          label="Completed" 
          value={completed} 
          icon={<CheckCircle2 size={20} />}
          color="bg-purple-50 text-purple-600 border-purple-100"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="card p-8 space-y-6">
          <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <TrendingUp size={20} className="text-brand-600" />
            Activity Summary
          </h3>
          <div className="space-y-4">
            <div className="flex justify-between items-center p-4 rounded-xl bg-slate-50 border border-slate-100">
              <span className="text-slate-600 font-medium">Completion Rate</span>
              <span className="text-xl font-bold text-slate-900">
                {total > 0 ? Math.round((completed / total) * 100) : 0}%
              </span>
            </div>
            <div className="flex justify-between items-center p-4 rounded-xl bg-slate-50 border border-slate-100">
              <span className="text-slate-600 font-medium">Sending vs Receiving</span>
              <span className="text-xl font-bold text-slate-900">
                {sending} / {receiving}
              </span>
            </div>
          </div>
        </div>

        <div className="card p-8 space-y-6">
          <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <Globe size={20} className="text-brand-600" />
            Top Countries
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Top Sent To</h4>
              {topSentTo.length > 0 ? (
                <div className="space-y-2">
                  {topSentTo.map(([country, count]) => (
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
              <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Top Received From</h4>
              {topReceivedFrom.length > 0 ? (
                <div className="space-y-2">
                  {topReceivedFrom.map(([country, count]) => (
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
      </div>
    </div>
  );
}

function StatCard({ label, value, color, icon }: { label: string, value: number, color: string, icon: React.ReactNode }) {
  return (
    <div className={`card p-6 flex flex-col gap-4 border-l-4 ${color}`}>
      <div className="flex items-center justify-between">
        <div className="text-sm font-bold uppercase tracking-wider opacity-70">{label}</div>
        <div className="p-2 rounded-lg bg-white shadow-sm border border-slate-100">{icon}</div>
      </div>
      <div className="text-4xl font-black">{value}</div>
    </div>
  );
}
