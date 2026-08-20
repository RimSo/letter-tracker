'use client';

import { useEffect, useRef, useState } from 'react';
import { supabase } from '@/lib/supabase';
import { Letter } from '@/types';
import { STATUSES, LetterStatus } from '@/constants/statuses';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Plus, Mail, ArrowRight, Calendar, MapPin, Search, LayoutGrid, List as ListIcon, Table as TableIcon, ChevronLeft, ChevronRight, ArrowUpDown, ChevronUp, ChevronDown, Globe, Paperclip, Link as LinkIcon, MoreVertical } from 'lucide-react';
import { format, differenceInDays } from 'date-fns';

const ITEMS_PER_PAGE = 10;
const COLUMN_VISIBILITY_STORAGE_KEY = 'dashboardTableColumns';

type LetterRow = Letter & { sources?: { name: string } | null };

const TABLE_COLUMNS = [
  { id: 'date', label: 'Date' },
  { id: 'nickname', label: 'Nickname' },
  { id: 'name', label: 'Name' },
  { id: 'where', label: 'Where' },
  { id: 'to', label: 'To' },
  { id: 'tracking', label: 'Tracking' },
  { id: 'source', label: 'Source' },
  { id: 'status', label: 'Status' },
  { id: 'days', label: 'Days' },
  { id: 'file', label: 'File' },
] as const;

type TableColumnId = typeof TABLE_COLUMNS[number]['id'];

export default function DashboardPage() {
  const [letters, setLetters] = useState<LetterRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<LetterStatus | 'All'>('All');
  const [viewMode, setViewMode] = useState<'grid' | 'list' | 'table'>('table');
  const [currentPage, setCurrentPage] = useState(1);
  const [sortConfig, setSortConfig] = useState<{ key: keyof Letter | 'where'; direction: 'asc' | 'desc' } | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [visibleColumns, setVisibleColumns] = useState<Set<TableColumnId>>(
    () => new Set(TABLE_COLUMNS.map(c => c.id))
  );
  const [isColumnMenuOpen, setIsColumnMenuOpen] = useState(false);
  const columnMenuRef = useRef<HTMLDivElement>(null);
  const router = useRouter();

  useEffect(() => {
    try {
      const saved = localStorage.getItem(COLUMN_VISIBILITY_STORAGE_KEY);
      if (!saved) return;
      const validIds = new Set(TABLE_COLUMNS.map(c => c.id));
      const parsed: TableColumnId[] = JSON.parse(saved).filter((id: string) => validIds.has(id as TableColumnId));
      if (parsed.length > 0) setVisibleColumns(new Set(parsed));
    } catch {
      // ignore malformed/unavailable storage
    }
  }, []);

  useEffect(() => {
    if (!isColumnMenuOpen) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (columnMenuRef.current && !columnMenuRef.current.contains(e.target as Node)) {
        setIsColumnMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isColumnMenuOpen]);

  const toggleColumn = (id: TableColumnId) => {
    setVisibleColumns(prev => {
      if (prev.has(id) && prev.size === 1) return prev;
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      localStorage.setItem(COLUMN_VISIBILITY_STORAGE_KEY, JSON.stringify([...next]));
      return next;
    });
  };

  useEffect(() => {
    async function checkUserAndFetchLetters() {
      setErrorMsg(null);
      const { data: { session } } = await supabase.auth.getSession();
      
      if (!session) {
        router.push('/login');
        return;
      }

      const { data, error } = await supabase
        .from('letters')
        .select('*, sources(name)')
        .order('sent_date', { ascending: false });
      
      if (error) {
        console.error('Error fetching letters:', error.message || error);
        setErrorMsg(error.message || 'Failed to fetch letters. Please check if the database tables are created.');
      } else {
        setLetters(data || []);
      }
      setLoading(false);
    }

    checkUserAndFetchLetters();
  }, [router]);

  // Reset to first page when search or filter changes
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, statusFilter]);

  const calculateDays = (letter: Letter) => {
    if (!letter.sent_date) return null;
    
    const startDate = new Date(letter.sent_date);
    const endDate = letter.is_completed && letter.received_date 
      ? new Date(letter.received_date) 
      : new Date();
    
    return differenceInDays(endDate, startDate);
  };

  const getStatusCount = (status: LetterStatus | 'All') => {
    return letters.filter(letter => {
      const matchesStatus = status === 'All' || 
                           (status === 'Sending' && letter.direction === 'sending' && letter.status === 'Active') ||
                           (status === 'Receiving' && letter.direction === 'receiving' && letter.status === 'Active') ||
                           letter.status === status;
      
      if (status === 'Delivered') {
        return letter.is_completed;
      }
      return matchesStatus;
    }).length;
  };

  const getStatusColor = (status: LetterStatus | 'All') => {
    switch (status) {
      case 'All': return 'bg-brand-600 text-white shadow-brand-200';
      case 'Sending': return 'bg-blue-600 text-white shadow-blue-200';
      case 'Receiving': return 'bg-indigo-600 text-white shadow-indigo-200';
      case 'Delivered': return 'bg-green-600 text-white shadow-green-200';
      case 'Draft': return 'bg-slate-600 text-white shadow-slate-200';
      case 'Returned': return 'bg-purple-600 text-white shadow-purple-200';
      case 'Lost': return 'bg-red-600 text-white shadow-red-200';
      default: return 'bg-brand-600 text-white shadow-brand-200';
    }
  };

  const getDaysColor = (days: number | null) => {
    if (days === null) return 'text-slate-400';
    if (days <= 7) return 'text-green-600 font-bold';
    if (days > 45) return 'text-red-600 font-bold';
    return 'text-slate-600';
  };

  const filteredLetters = letters.filter(letter => {
    const searchLower = searchTerm.toLowerCase();
    const matchesSearch = 
      (letter.nickname || '').toLowerCase().includes(searchLower) ||
      (letter.name || '').toLowerCase().includes(searchLower) ||
      (letter.to_country || '').toLowerCase().includes(searchLower) ||
      (letter.from_country || '').toLowerCase().includes(searchLower) ||
      (letter.to_city || '').toLowerCase().includes(searchLower) ||
      (letter.from_city || '').toLowerCase().includes(searchLower) ||
      (letter.tracking || '').toLowerCase().includes(searchLower) ||
      (letter.to_zip_code || '').toLowerCase().includes(searchLower) ||
      (letter.from_zip_code || '').toLowerCase().includes(searchLower) ||
      (letter.sources?.name || '').toLowerCase().includes(searchLower);
    
    const matchesStatus = statusFilter === 'All' || 
                         (statusFilter === 'Sending' && letter.direction === 'sending' && letter.status === 'Active') ||
                         (statusFilter === 'Receiving' && letter.direction === 'receiving' && letter.status === 'Active') ||
                         letter.status === statusFilter;
    
    if (statusFilter === 'Delivered') {
      return matchesSearch && letter.is_completed;
    }
    return matchesSearch && matchesStatus;
  });

  const sortedLetters = [...filteredLetters].sort((a, b) => {
    if (!sortConfig) return 0;
    
    let aValue: any;
    let bValue: any;

    if (sortConfig.key === 'where') {
      aValue = a.from_country;
      bValue = b.from_country;
    } else if (sortConfig.key === 'days') {
      aValue = calculateDays(a);
      bValue = calculateDays(b);
    } else {
      aValue = a[sortConfig.key];
      bValue = b[sortConfig.key];
    }

    if (aValue === bValue) return 0;
    if (aValue === null || aValue === undefined) return 1;
    if (bValue === null || bValue === undefined) return -1;

    const modifier = sortConfig.direction === 'asc' ? 1 : -1;
    if (aValue < bValue) return -1 * modifier;
    if (aValue > bValue) return 1 * modifier;
    return 0;
  });

  const totalPages = Math.ceil(sortedLetters.length / ITEMS_PER_PAGE);
  const paginatedLetters = sortedLetters.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );

  const handleSort = (key: keyof Letter | 'where') => {
    let direction: 'asc' | 'desc' = 'asc';
    if (sortConfig && sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  const getSortIcon = (key: keyof Letter | 'where') => {
    if (!sortConfig || sortConfig.key !== key) return <ArrowUpDown size={14} className="ml-1 opacity-20" />;
    return sortConfig.direction === 'asc' 
      ? <ChevronUp size={14} className="ml-1 text-brand-600" /> 
      : <ChevronDown size={14} className="ml-1 text-brand-600" />;
  };


  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-brand-600"></div>
        <p className="mt-4 text-slate-500 font-medium">Loading your letters...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 tracking-tight">Your Letters</h1>
          <p className="text-slate-500 mt-1">Manage and track your correspondence</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="bg-slate-100 p-1 rounded-lg flex items-center">
            <button
              onClick={() => setViewMode('grid')}
              className={`p-2 rounded-md transition-all ${viewMode === 'grid' ? 'bg-white text-brand-600 shadow-sm' : 'text-slate-500 hover:text-slate-700'}`}
              title="Grid View"
            >
              <LayoutGrid size={20} />
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`p-2 rounded-md transition-all ${viewMode === 'list' ? 'bg-white text-brand-600 shadow-sm' : 'text-slate-500 hover:text-slate-700'}`}
              title="List View"
            >
              <ListIcon size={20} />
            </button>
            <button
              onClick={() => setViewMode('table')}
              className={`p-2 rounded-md transition-all ${viewMode === 'table' ? 'bg-white text-brand-600 shadow-sm' : 'text-slate-500 hover:text-slate-700'}`}
              title="Table View"
            >
              <TableIcon size={20} />
            </button>
          </div>
          {viewMode === 'table' && (
            <div className="relative" ref={columnMenuRef}>
              <button
                onClick={() => setIsColumnMenuOpen(prev => !prev)}
                className={`p-2 rounded-lg border transition-colors ${
                  isColumnMenuOpen
                    ? 'border-brand-300 bg-brand-50 text-brand-600'
                    : 'border-slate-200 text-slate-500 hover:bg-slate-50 hover:text-slate-700'
                }`}
                title="Choose columns"
              >
                <MoreVertical size={20} />
              </button>
              {isColumnMenuOpen && (
                <div className="absolute right-0 mt-2 w-56 bg-white border border-slate-200 rounded-xl shadow-lg z-20 py-2">
                  <p className="px-4 py-1.5 text-xs font-bold text-slate-400 uppercase tracking-wider">Columns</p>
                  {TABLE_COLUMNS.map(col => (
                    <label
                      key={col.id}
                      className="flex items-center gap-3 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50 cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={visibleColumns.has(col.id)}
                        onChange={() => toggleColumn(col.id)}
                        className="rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                      />
                      {col.label}
                    </label>
                  ))}
                </div>
              )}
            </div>
          )}
          <Link
            href="/add" 
            className="btn-primary inline-flex items-center justify-center gap-2"
          >
            <Plus size={20} />
            <span className="hidden sm:inline">Add New Letter</span>
            <span className="sm:hidden">Add</span>
          </Link>
        </div>
      </div>

      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
          <Search size={18} />
        </div>
        <input
          type="text"
          placeholder="Search by any info (name, country, city, tracking...)"
          className="w-full pl-10 input-base"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </div>

      <div className="flex flex-wrap gap-2 overflow-x-auto pb-1 scrollbar-hide">
        <button
          onClick={() => setStatusFilter('All')}
          className={`px-4 py-1.5 rounded-full text-sm font-medium transition-all whitespace-nowrap flex items-center gap-2 ${
            statusFilter === 'All'
              ? `${getStatusColor('All')} shadow-sm`
              : 'bg-white text-slate-600 border border-slate-200 hover:border-brand-300 hover:text-brand-600'
          }`}
        >
          <span>All</span>
          <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
            statusFilter === 'All' ? 'bg-white/20' : 'bg-slate-100 text-slate-500'
          }`}>
            {getStatusCount('All')}
          </span>
        </button>
        {STATUSES.map((status) => (
          <button
            key={status}
            onClick={() => setStatusFilter(status)}
            className={`px-4 py-1.5 rounded-full text-sm font-medium transition-all whitespace-nowrap flex items-center gap-2 ${
              statusFilter === status
                ? `${getStatusColor(status)} shadow-sm`
                : 'bg-white text-slate-600 border border-slate-200 hover:border-brand-300 hover:text-brand-600'
            }`}
          >
            <span>{status}</span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
              statusFilter === status ? 'bg-white/20' : 'bg-slate-100 text-slate-500'
            }`}>
              {getStatusCount(status)}
            </span>
          </button>
        ))}
      </div>

      {errorMsg && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl flex items-center gap-3">
          <div className="bg-red-100 p-1 rounded-full">
            <Plus size={16} className="rotate-45" />
          </div>
          <p className="font-medium">{errorMsg}</p>
        </div>
      )}

      {filteredLetters.length === 0 ? (
        <div className="card p-12 text-center flex flex-col items-center">
          <div className="bg-slate-50 p-4 rounded-full text-slate-400 mb-4">
            <Mail size={40} />
          </div>
          <h3 className="text-lg font-semibold text-slate-900">No letters found</h3>
          <p className="text-slate-500 mt-1 max-w-xs mx-auto">
            {searchTerm ? "We couldn't find any letters matching your search." : "You haven't added any letters yet. Start by adding your first one!"}
          </p>
          {!searchTerm && statusFilter !== 'Returned' && statusFilter !== 'Lost' && (
            <Link href="/add" className="btn-secondary mt-6 inline-flex items-center gap-2">
              <Plus size={18} /> Add First Letter
            </Link>
          )}
        </div>
      ) : viewMode === 'grid' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {paginatedLetters.map((letter) => (
            <div 
              key={letter.id} 
              onClick={() => router.push(`/edit/${letter.id}`)}
              className="card group hover:border-brand-300 hover:shadow-md transition-all duration-300 flex flex-col cursor-pointer"
            >
              <div className="p-5 flex-grow">
                <div className="flex justify-between items-start mb-4">
                  <div className="bg-brand-50 text-brand-700 p-2 rounded-xl group-hover:bg-brand-600 group-hover:text-white transition-colors duration-300">
                    <Mail size={20} />
                  </div>
                  <span className={`px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${
                    letter.is_completed 
                      ? 'bg-green-100 text-green-700 border border-green-200' 
                      : 'bg-amber-100 text-amber-700 border border-amber-200'
                  }`}>
                    {letter.status === 'Active' 
                      ? (letter.direction === 'sending' ? 'Sending' : 'Receiving') 
                      : letter.status}
                  </span>
                </div>
                
                <h3 className="text-xl font-bold text-slate-900 group-hover:text-brand-600 transition-colors">
                  {letter.nickname || letter.name}
                </h3>
                
                <div className="mt-4 space-y-2">
                  <div className="flex items-center text-sm text-slate-500 gap-2">
                    <MapPin size={16} />
                    <span>{letter.from_country} → {letter.to_country}</span>
                  </div>
                  <div className="flex items-center text-sm text-slate-500 gap-2">
                    <Calendar size={16} />
                    <span>
                      {letter.sent_date ? format(new Date(letter.sent_date), 'PPP') : 'Draft'}
                    </span>
                  </div>
                  {letter.tracking && (
                    <div className="flex items-center text-sm text-brand-600 font-medium gap-2">
                      <Globe size={16} />
                      <a 
                        href={`https://t.17track.net/en#nums=${letter.tracking}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:underline"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {letter.tracking}
                      </a>
                    </div>
                  )}
                  {letter.attachment_url && (
                    <div className="flex items-center text-sm text-brand-600 font-medium gap-2">
                      <Paperclip size={16} />
                      <span>Attachment included</span>
                    </div>
                  )}
                  {letter.sources?.name && (
                    <div className="flex items-center text-sm text-purple-600 font-medium gap-2">
                      <LinkIcon size={16} />
                      <span>Source: {letter.sources.name}</span>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="px-5 py-3 bg-slate-50 border-t border-slate-100 flex items-center justify-between text-brand-600 font-semibold text-sm">
                <span>View Details</span>
                <ArrowRight size={16} className="group-hover:translate-x-1 transition-transform" />
              </div>
            </div>
          ))}
        </div>
      ) : viewMode === 'list' ? (
        <div className="space-y-3">
          {paginatedLetters.map((letter) => (
            <div 
              key={letter.id} 
              onClick={() => router.push(`/edit/${letter.id}`)}
              className="card group hover:border-brand-300 hover:shadow-sm transition-all duration-300 flex items-center p-4 gap-4 cursor-pointer"
            >
              <div className="bg-brand-50 text-brand-700 p-2.5 rounded-xl group-hover:bg-brand-600 group-hover:text-white transition-colors duration-300 shrink-0">
                <Mail size={22} />
              </div>
              
              <div className="flex-grow min-w-0">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                  <h3 className="text-lg font-bold text-slate-900 group-hover:text-brand-600 transition-colors truncate">
                    {letter.nickname || letter.name}
                  </h3>
                  <span className={`self-start px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                    letter.is_completed 
                      ? 'bg-green-50 text-green-700 border border-green-100' 
                      : 'bg-amber-50 text-amber-700 border border-amber-100'
                  }`}>
                    {letter.status === 'Active' 
                      ? (letter.direction === 'sending' ? 'Sending' : 'Receiving') 
                      : letter.status}
                  </span>
                </div>
                
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1">
                  <div className="flex items-center text-xs text-slate-500 gap-1.5">
                    <MapPin size={14} className="text-slate-400" />
                    <span>{letter.from_country} → {letter.to_country}</span>
                  </div>
                  <div className="flex items-center text-xs text-slate-500 gap-1.5">
                    <Calendar size={14} className="text-slate-400" />
                    <span>
                      {letter.sent_date ? format(new Date(letter.sent_date), 'MMM d, yyyy') : 'Draft'}
                    </span>
                  </div>
                  {letter.tracking && (
                    <div className="flex items-center text-xs text-brand-600 font-medium gap-1.5">
                      <Globe size={14} />
                      <a 
                        href={`https://t.17track.net/en#nums=${letter.tracking}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:underline"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {letter.tracking}
                      </a>
                    </div>
                  )}
                  {letter.attachment_url && (
                    <div className="flex items-center text-xs text-brand-600 font-medium gap-1.5">
                      <Paperclip size={14} />
                      <span>Has attachment</span>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="shrink-0 text-slate-300 group-hover:text-brand-600 transition-colors">
                <ArrowRight size={20} className="group-hover:translate-x-1 transition-transform" />
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="card overflow-hidden overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[600px]">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-100">
                {visibleColumns.has('date') && (
                  <th
                    className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider text-left cursor-pointer hover:bg-slate-100 transition-colors"
                    onClick={() => handleSort('sent_date')}
                  >
                    <div className="flex items-center">Date {getSortIcon('sent_date')}</div>
                  </th>
                )}
                {visibleColumns.has('nickname') && (
                  <th
                    className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider text-left cursor-pointer hover:bg-slate-100 transition-colors"
                    onClick={() => handleSort('nickname')}
                  >
                    <div className="flex items-center">Nickname {getSortIcon('nickname')}</div>
                  </th>
                )}
                {visibleColumns.has('name') && (
                  <th
                    className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider text-left cursor-pointer hover:bg-slate-100 transition-colors"
                    onClick={() => handleSort('name')}
                  >
                    <div className="flex items-center">Name {getSortIcon('name')}</div>
                  </th>
                )}
                {visibleColumns.has('where') && (
                  <th
                    className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider text-left cursor-pointer hover:bg-slate-100 transition-colors"
                    onClick={() => handleSort('where')}
                  >
                    <div className="flex items-center">Where {getSortIcon('where')}</div>
                  </th>
                )}
                {visibleColumns.has('to') && (
                  <th
                    className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider text-left cursor-pointer hover:bg-slate-100 transition-colors"
                    onClick={() => handleSort('to_country')}
                  >
                    <div className="flex items-center">To {getSortIcon('to_country')}</div>
                  </th>
                )}
                {visibleColumns.has('tracking') && (
                  <th
                    className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider text-left cursor-pointer hover:bg-slate-100 transition-colors"
                    onClick={() => handleSort('tracking')}
                  >
                    <div className="flex items-center">Tracking {getSortIcon('tracking')}</div>
                  </th>
                )}
                {visibleColumns.has('source') && (
                  <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider text-left">
                    Source
                  </th>
                )}
                {visibleColumns.has('status') && (
                  <th
                    className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider text-left cursor-pointer hover:bg-slate-100 transition-colors"
                    onClick={() => handleSort('status')}
                  >
                    <div className="flex items-center">Status {getSortIcon('status')}</div>
                  </th>
                )}
                {visibleColumns.has('days') && (
                  <th
                    className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider text-left cursor-pointer hover:bg-slate-100 transition-colors"
                    onClick={() => handleSort('days')}
                  >
                    <div className="flex items-center">Days {getSortIcon('days')}</div>
                  </th>
                )}
                {visibleColumns.has('file') && (
                  <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider text-center">
                    File
                  </th>
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {paginatedLetters.map((letter) => (
                <tr 
                  key={letter.id} 
                  onClick={() => router.push(`/edit/${letter.id}`)}
                  className="hover:bg-slate-50/50 cursor-pointer transition-colors group"
                >
                  {visibleColumns.has('date') && (
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-600 text-left">
                      {letter.sent_date
                        ? format(new Date(letter.sent_date), 'MMM d, yyyy')
                        : letter.received_date
                          ? `${format(new Date(letter.received_date), 'MMM d, yyyy')} (received)`
                          : 'Draft'}
                    </td>
                  )}
                  {visibleColumns.has('nickname') && (
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-slate-900 text-left">
                      {letter.nickname || '-'}
                    </td>
                  )}
                  {visibleColumns.has('name') && (
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-600 text-left">
                      {letter.name || '-'}
                    </td>
                  )}
                  {visibleColumns.has('where') && (
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-600 text-left">
                      {letter.from_country}
                    </td>
                  )}
                  {visibleColumns.has('to') && (
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-600 text-left">
                      {letter.to_country}
                    </td>
                  )}
                  {visibleColumns.has('tracking') && (
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-600 text-left">
                      {letter.tracking ? (
                        <a
                          href={`https://t.17track.net/en#nums=${letter.tracking}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-brand-600 hover:underline flex items-center gap-1"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {letter.tracking}
                          <Globe size={12} />
                        </a>
                      ) : (
                        '-'
                      )}
                    </td>
                  )}
                  {visibleColumns.has('source') && (
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-600 text-left">
                      {letter.sources?.name || '-'}
                    </td>
                  )}
                  {visibleColumns.has('status') && (
                    <td className="px-6 py-4 whitespace-nowrap text-left">
                      <span className={`inline-flex px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${
                        letter.is_completed
                          ? 'bg-green-100 text-green-700'
                          : 'bg-amber-100 text-amber-700'
                      }`}>
                        {letter.status === 'Active'
                          ? (letter.direction === 'sending' ? 'Sending' : 'Receiving')
                          : letter.status}
                      </span>
                    </td>
                  )}
                  {visibleColumns.has('days') && (
                    <td className="px-6 py-4 whitespace-nowrap text-left text-sm">
                      {(() => {
                        const days = calculateDays(letter);
                        return (
                          <span className={getDaysColor(days)}>
                            {days !== null ? `${days} days` : '-'}
                          </span>
                        );
                      })()}
                    </td>
                  )}
                  {visibleColumns.has('file') && (
                    <td className="px-6 py-4 whitespace-nowrap text-center text-slate-400">
                      {letter.attachment_url ? (
                        <Paperclip size={18} className="mx-auto text-brand-600" />
                      ) : (
                        '-'
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-4 border-t border-slate-100">
          <p className="text-sm text-slate-500">
            Showing <span className="font-medium text-slate-900">{((currentPage - 1) * ITEMS_PER_PAGE) + 1}</span> to <span className="font-medium text-slate-900">{Math.min(currentPage * ITEMS_PER_PAGE, sortedLetters.length)}</span> of <span className="font-medium text-slate-900">{sortedLetters.length}</span> results
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
              disabled={currentPage === 1}
              className="p-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft size={20} />
            </button>
            
            <div className="flex items-center gap-1">
              {[...Array(totalPages)].map((_, i) => {
                const pageNum = i + 1;
                // Only show first page, last page, current page, and one around current page
                if (
                  pageNum === 1 || 
                  pageNum === totalPages || 
                  (pageNum >= currentPage - 1 && pageNum <= currentPage + 1)
                ) {
                  return (
                    <button
                      key={pageNum}
                      onClick={() => setCurrentPage(pageNum)}
                      className={`w-10 h-10 rounded-lg text-sm font-medium transition-all ${
                        currentPage === pageNum 
                          ? 'bg-brand-600 text-white shadow-sm shadow-brand-200' 
                          : 'text-slate-600 hover:bg-slate-100'
                      }`}
                    >
                      {pageNum}
                    </button>
                  );
                } else if (
                  pageNum === currentPage - 2 || 
                  pageNum === currentPage + 2
                ) {
                  return <span key={pageNum} className="px-1 text-slate-400">...</span>;
                }
                return null;
              })}
            </div>

            <button
              onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
              disabled={currentPage === totalPages}
              className="p-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronRight size={20} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
