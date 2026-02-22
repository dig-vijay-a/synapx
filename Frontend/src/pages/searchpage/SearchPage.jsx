import { useState, useRef, useEffect, useMemo } from 'react';
import { useLocation, useNavigate, Navigate } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import logoImg from '../assets/logo.png';
import './SearchPage.css';



/**
 * Encrypt a plaintext string using RSA-OAEP with the server's public key.
 * Uses the browser's built-in SubtleCrypto API — no library needed.
 */
async function rsaEncryptQuery(publicKeyPem, plaintext) {
    // Strip PEM headers and decode base64
    const b64 = publicKeyPem
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\s+/g, '');
    const binaryDer = Uint8Array.from(atob(b64), c => c.charCodeAt(0));

    const key = await crypto.subtle.importKey(
        'spki',
        binaryDer.buffer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt'],
    );

    const enc = new TextEncoder();
    const ct = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, enc.encode(plaintext));
    return btoa(String.fromCharCode(...new Uint8Array(ct)));
}

/**
 * Decrypt the server's AES-256-GCM encrypted response in the browser.
 */
async function aesDecryptResponse(ciphertextB64, keyB64, nonceB64) {
    const fromB64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

    const key = await crypto.subtle.importKey(
        'raw',
        fromB64(keyB64),
        { name: 'AES-GCM' },
        false,
        ['decrypt'],
    );

    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromB64(nonceB64) },
        key,
        fromB64(ciphertextB64),
    );

    return JSON.parse(new TextDecoder().decode(plaintext));
}


function SearchPage() {
    const location = useLocation();
    const navigate = useNavigate();

    // if accessed directly without state, redirect to upload
    if (!location.state || !location.state.fileId) {
        return <Navigate to="/" replace />;
    }

    const { fileId, fileName } = location.state;
    const onBack = () => navigate('/');

    const [query, setQuery] = useState('');
    const [isSearching, setIsSearching] = useState(false);
    const [results, setResults] = useState(null);
    const [hasSearched, setHasSearched] = useState(false);
    const [searchError, setSearchError] = useState('');
    const [vmInfo, setVmInfo] = useState(null);
    const inputRef = useRef(null);

    useEffect(() => { inputRef.current?.focus(); }, []);

    const handleSearch = async (e) => {
        e.preventDefault();
        if (!query.trim()) return;

        setIsSearching(true);
        setHasSearched(false);
        setSearchError('');
        setResults(null);

        try {
            // Step 1: Get a fresh session + server RSA public key
            const sessionRes = await fetch(`${API_BASE}/api/session?file_id=${fileId}`);
            const sessionData = await sessionRes.json();
            if (!sessionRes.ok) throw new Error(sessionData.error || 'Session creation failed');

            const { session_id, public_key_pem } = sessionData;

            // Step 2: Encrypt the search query with the server's RSA-OAEP public key
            const encryptedQueryB64 = await rsaEncryptQuery(public_key_pem, query.trim());

            // Step 3: Submit the encrypted query
            const searchRes = await fetch(`${API_BASE}/api/search`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id, encrypted_query_b64: encryptedQueryB64 }),
            });
            const searchData = await searchRes.json();
            if (!searchRes.ok) throw new Error(searchData.error || 'Search failed');

            // Step 4: Decrypt the response in the browser (E2E)
            const decrypted = await aesDecryptResponse(
                searchData.ciphertext_b64,
                searchData.key_b64,
                searchData.nonce_b64,
            );

            if (decrypted.ok === false) {
                throw new Error(decrypted.error || 'The TEE worker failed to process your search.');
            }

            setResults(decrypted.results || []);
            setVmInfo({ remaining: searchData.searches_remaining });

        } catch (err) {
            setSearchError(err.message || 'An unexpected error occurred. Is the backend running?');
        } finally {
            setIsSearching(false);
            setHasSearched(true);
        }
    };

    const priorityColor = (p) => {
        if (p === 'HIGH') return { dot: '#22c55e', badge: 'badge-high' };
        if (p === 'MEDIUM') return { dot: '#f59e0b', badge: 'badge-med' };
        return { dot: '#64748b', badge: 'badge-low' };
    };

    // Render excerpt: clean PDF object strings, bold the **keyword** markers
    const renderExcerpt = (text, matchType) => {
        let cleanText = text
            // Strip out raw PDF stream dictionary elements and object references
            .replace(/\/[A-Za-z]+[\w+\-\/]*/g, '')
            .replace(/<<.*?>>/g, '')
            .replace(/\b\d+\s+\d+\s+(obj|R)\b/g, '')
            .replace(/\bendobj\b/g, '')
            .replace(/[^\w\s.,?!*'()\[\]-]/g, ' ')
            .replace(/\s{2,}/g, ' ')
            .trim();

        const parts = cleanText.split(/(\*\*[^*]+\*\*)/g);
        const hlClass = `hl-${(matchType || 'exact').toLowerCase()}`;

        return parts.map((part, i) =>
            part.startsWith('**') && part.endsWith('**')
                ? <strong key={i} className={`kw-highlight ${hlClass}`}>{part.slice(2, -2)}</strong>
                : <span key={i}>{part}</span>
        );
    };

    // Construct chart data 
    const chartData = useMemo(() => {
        if (!results) return [];
        const pageMap = {};
        results.forEach(r => {
            if (!pageMap[r.page]) pageMap[r.page] = 0;
            pageMap[r.page] += r.count;
        });
        return Object.keys(pageMap)
            .map(p => ({ page: `Page ${p}`, hits: pageMap[p], rawPage: parseInt(p) }))
            .sort((a, b) => a.rawPage - b.rawPage);
    }, [results]);

    return (
        <div className="search-page">
            <div className="s-orb s-orb-1" />
            <div className="s-orb s-orb-2" />

            <div className="search-container">
                {/* Top bar */}
                <div className="search-topbar">
                    <button className="back-btn" onClick={onBack}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                            <polyline points="15 18 9 12 15 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                        Back
                    </button>

                    <div className="topbar-brand">
                        <img src={logoImg} alt="CipherSearch Logo" style={{ width: '28px', height: '28px', objectFit: 'contain' }} />
                        <span>CipherSearch</span>
                    </div>

                    <div className="doc-pill">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none">
                            <path d="M13 2H6C5.47 2 4.96 2.21 4.59 2.59C4.21 2.96 4 3.47 4 4V20C4 20.53 4.21 21.04 4.59 21.41C4.96 21.79 5.47 22 6 22H18C18.53 22 19.04 21.79 19.41 21.41C19.79 21.04 20 20.53 20 20V9L13 2Z" stroke="#818cf8" strokeWidth="1.5" />
                        </svg>
                        <span className="doc-name">{fileName}</span>
                    </div>
                </div>



                {/* Hero */}
                <div className="search-hero">
                    <h1 className="search-hero-title">Secure Keyword Search</h1>
                    <p className="search-hero-sub">
                        Query runs inside an isolated TEE session · E2E encrypted · Constant-time response
                    </p>
                </div>

                {/* Search bar */}
                <form className="search-form" onSubmit={handleSearch}>
                    <div className="search-bar-wrapper">
                        <svg className="search-icon" width="20" height="20" viewBox="0 0 24 24" fill="none">
                            <circle cx="11" cy="11" r="8" stroke="#475569" strokeWidth="1.5" />
                            <line x1="21" y1="21" x2="16.65" y2="16.65" stroke="#475569" strokeWidth="1.5" strokeLinecap="round" />
                        </svg>
                        <input
                            ref={inputRef}
                            type="text"
                            className="search-input"
                            placeholder="Enter keyword to search..."
                            value={query}
                            onChange={(e) => setQuery(e.target.value)}
                            id="search-input"
                        />
                        {query && (
                            <button
                                type="button"
                                className="search-clear"
                                onClick={() => { setQuery(''); setResults(null); setHasSearched(false); setSearchError(''); }}
                            >
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                                    <line x1="18" y1="6" x2="6" y2="18" stroke="#64748b" strokeWidth="2" strokeLinecap="round" />
                                    <line x1="6" y1="6" x2="18" y2="18" stroke="#64748b" strokeWidth="2" strokeLinecap="round" />
                                </svg>
                            </button>
                        )}
                        <button className="search-submit" type="submit" disabled={!query.trim() || isSearching}>
                            {isSearching ? <div className="s-spinner" /> : (
                                <>
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                                        <circle cx="11" cy="11" r="8" stroke="currentColor" strokeWidth="2" />
                                        <line x1="21" y1="21" x2="16.65" y2="16.65" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                                    </svg>
                                    Search
                                </>
                            )}
                        </button>
                    </div>
                </form>

                {/* VM status badge */}
                {vmInfo && (
                    <div className="vm-status-bar">
                        <span className="vm-dot" />
                        TEE Active — VM resets after <strong>{vmInfo.remaining}</strong> more search{vmInfo.remaining !== 1 ? 'es' : ''}
                    </div>
                )}

                {/* Error */}
                {searchError && (
                    <div className="search-error-banner">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                            <circle cx="12" cy="12" r="10" stroke="#f87171" strokeWidth="1.5" />
                            <line x1="12" y1="8" x2="12" y2="12" stroke="#f87171" strokeWidth="1.5" strokeLinecap="round" />
                            <line x1="12" y1="16" x2="12.01" y2="16" stroke="#f87171" strokeWidth="2" strokeLinecap="round" />
                        </svg>
                        {searchError}
                    </div>
                )}

                {/* Loading */}
                {isSearching && (
                    <div className="results-loading">
                        <div className="loading-bars">
                            <span /><span /><span /><span />
                        </div>
                        <p>Querying inside TEE · decrypting · searching...</p>
                    </div>
                )}

                {/* Results */}
                {hasSearched && results && !isSearching && !searchError && (
                    <div className="results-section">
                        <div className="results-header">
                            <span className="results-count">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" style={{ marginRight: '6px' }}>
                                    <path d="M9 11l3 3L22 4" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                    <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                </svg>
                                {results.length} result{results.length !== 1 ? 's' : ''} for <em>"{query}"</em>
                            </span>
                            <span className="results-meta">Priority-ranked · TEE-verified</span>
                        </div>

                        {results.length === 0 ? (
                            <div className="no-results">
                                <svg width="48" height="48" viewBox="0 0 24 24" fill="none">
                                    <circle cx="11" cy="11" r="8" stroke="#334155" strokeWidth="1.5" />
                                    <line x1="21" y1="21" x2="16.65" y2="16.65" stroke="#334155" strokeWidth="1.5" strokeLinecap="round" />
                                    <line x1="8" y1="8" x2="14" y2="14" stroke="#334155" strokeWidth="1.5" strokeLinecap="round" />
                                    <line x1="14" y1="8" x2="8" y2="14" stroke="#334155" strokeWidth="1.5" strokeLinecap="round" />
                                </svg>
                                <p>No matches found for <em>"{query}"</em></p>
                                <span>Try a different keyword or check the document contents</span>
                            </div>
                        ) : (
                            <div className="search-results-layout">
                                <div className="results-list-column">
                                    <div className="results-list">
                                        {results.map((r, i) => {
                                            const pc = priorityColor(r.priority);
                                            return (
                                                <div key={i} className="result-card" style={{ animationDelay: `${i * 80}ms` }}>
                                                    <div className="result-top">
                                                        <div className="result-left">
                                                            <span className={`priority-badge ${pc.badge}`}>
                                                                <span className="priority-dot" style={{ background: pc.dot }} />
                                                                {r.priority}
                                                            </span>
                                                            <span className={`match-type-badge ${r.match_type.toLowerCase()}-match`}>
                                                                {r.match_type}
                                                            </span>
                                                            <span className="result-page">Page {r.page}</span>
                                                            <span className="result-count">{r.count} hit{r.count !== 1 ? 's' : ''}</span>
                                                        </div>
                                                        <div className="score-bar-wrapper">
                                                            <div className="score-bar" style={{ width: `${r.score * 100}%` }} />
                                                            <span className="score-label">{(r.score * 100).toFixed(0)}%</span>
                                                        </div>
                                                    </div>
                                                    <p className="result-excerpt">{renderExcerpt(r.excerpt, r.match_type)}</p>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>

                                <div className="chart-column">
                                    {chartData.length > 0 && (
                                        <div className="chart-container" style={{ height: 220, background: 'rgba(15,23,42,0.8)', padding: '20px', borderRadius: '14px', border: '1px solid rgba(255,255,255,0.06)' }}>
                                            <h4 style={{ color: '#94a3b8', margin: '0 0 15px 0', fontSize: '0.85rem' }}>Search Hits per Page</h4>
                                            <ResponsiveContainer width="100%" height="100%">
                                                <BarChart data={chartData}>
                                                    <XAxis dataKey="page" tick={{ fill: '#64748b', fontSize: 12 }} stroke="#334155" />
                                                    <YAxis tick={{ fill: '#64748b', fontSize: 12 }} stroke="#334155" allowDecimals={false} />
                                                    <Tooltip
                                                        contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '8px' }}
                                                        labelStyle={{ color: '#e2e8f0' }}
                                                        itemStyle={{ color: '#38bdf8' }}
                                                    />
                                                    <Bar dataKey="hits" fill="url(#colorHits)" radius={[4, 4, 0, 0]} />
                                                    <defs>
                                                        <linearGradient id="colorHits" x1="0" y1="0" x2="0" y2="1">
                                                            <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.8} />
                                                            <stop offset="95%" stopColor="#6366f1" stopOpacity={0.8} />
                                                        </linearGradient>
                                                    </defs>
                                                </BarChart>
                                            </ResponsiveContainer>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* Tips (initial state) */}
                {!hasSearched && !isSearching && (
                    <div className="search-tips">
                        <div className="tip-item">
                            <span className="tip-icon">⚡</span>
                            <span>Priority-aware results rank the most security-critical matches first</span>
                        </div>
                        <div className="tip-item">
                            <span className="tip-icon">🔒</span>
                            <span>Query encrypted with RSA-OAEP · Response encrypted with AES-256-GCM · Session killed after reply</span>
                        </div>
                        <div className="tip-item">
                            <span className="tip-icon">🖥️</span>
                            <span>Each search runs in an isolated TEE subprocess · VM resets every {10} searches</span>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

export default SearchPage;
