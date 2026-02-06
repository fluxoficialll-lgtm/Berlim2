
import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { authService } from '../services/authService';
import { trackingService } from '../services/trackingService';
import { API_BASE } from '../apiConfig';
import { LoginInitialCard } from '../features/auth/components/LoginInitialCard';
import { LoginEmailCard } from '../features/auth/components/LoginEmailCard';
import { User } from '@/types';

declare const google: any;

export const Login: React.FC = () => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);
    const [authProcessing, setAuthProcessing] = useState(false);
    const [error, setError] = useState('');
    
    // State for email/password form
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [showEmailForm, setShowEmailForm] = useState(false);
    
    const GOOGLE_BTN_ID = 'googleButtonDiv';

    // Detect affiliate refs from URL params
    useEffect(() => {
        trackingService.captureUrlParams();
    }, []);

    // Check if user is already authenticated
    useEffect(() => {
        if (authService.isAuthenticated()) {
            const user = authService.getCurrentUser();
            if (user) {
                const nextStep = user.isBanned ? '/banned' : (!user.isProfileCompleted ? '/complete-profile' : '/feed');
                navigate(nextStep, { replace: true });
            }
        } else {
            setLoading(false);
        }
    }, [navigate]);

    // Handler for Google's credential response
    const handleGoogleLogin = useCallback(async (response: any) => {
        if (authProcessing) return;
        setAuthProcessing(true);
        setError('');
        try {
            if (!response || !response.credential) throw new Error("Credencial do Google inválida.");
            const referredBy = trackingService.getAffiliateRef() || undefined;
            const result = await authService.loginWithGoogle(response.credential, referredBy);
            navigate(result.nextStep, { replace: true });
        } catch (err: any) {
            setError(err.message || 'Falha ao autenticar com Google.');
            setAuthProcessing(false);
        }
    }, [navigate, authProcessing]);

    // Handler for traditional email/password login
    const handleEmailLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!email || !password || authProcessing) return;
        setAuthProcessing(true);
        setError('');
        try {
            const result = await authService.login(email, password);
            navigate(result.nextStep, { replace: true });
        } catch (err: any) {
            setError(err.message || 'Credenciais inválidas.');
            setAuthProcessing(false);
        }
    };

    // Initialize Google Sign-In button
    useEffect(() => {
        if (showEmailForm || loading) return;

        const initGoogle = async () => {
            try {
                const res = await fetch(`${API_BASE}/api/auth/config`);
                if (!res.ok) return;
                const { clientId } = await res.json();
                if (!clientId || clientId.includes("CONFIGURADO")) return;

                if (typeof google !== 'undefined' && google.accounts) {
                    google.accounts.id.initialize({ client_id: clientId, callback: handleGoogleLogin });
                    const btnDiv = document.getElementById(GOOGLE_BTN_ID);
                    if (btnDiv) {
                         google.accounts.id.renderButton(btnDiv, { theme: 'filled_black', size: 'large', width: '400' });
                    }
                }
            } catch (err) {
                console.error("Failed to init Google Sign-In", err);
            }
        };

        const-script = document.createElement('script');
        script.src = "https://accounts.google.com/gsi/client";
        script.async = true;
        script.defer = true;
        script.onload = initGoogle;
        document.body.appendChild(script);

        return () => {
            document.body.removeChild(script);
        };
    }, [showEmailForm, loading, handleGoogleLogin]);

    if (loading) return null; // Render nothing while checking auth status

    return (
        <div className="min-h-screen w-full flex flex-col items-center justify-center bg-[#050505] text-white font-['Inter'] relative overflow-hidden">
            {/* Background decorative elements */}
            <div className="absolute inset-0 z-0 pointer-events-none">
                <div className="absolute top-[-20%] left-[-10%] w-[600px] h-[600px] bg-blue-900/10 rounded-full blur-[120px]"></div>
                <div className="absolute bottom-[-20%] right-[-10%] w-[500px] h-[500px] bg-indigo-900/10 rounded-full blur-[100px]"></div>
            </div>

            <div className="w-full max-w-[400px] mx-4 bg-white/5 backdrop-blur-2xl rounded-[32px] p-10 border border-white/10 shadow-2xl relative z-10 flex flex-col items-center">
                {showEmailForm ? (
                    <LoginEmailCard 
                        email={email}
                        setEmail={setEmail}
                        password={password}
                        setPassword={setPassword}
                        onSubmit={handleEmailLogin}
                        onBackToGoogle={() => setShowEmailForm(false)}
                        loading={authProcessing}
                        error={error}
                    />
                ) : (
                    <LoginInitialCard 
                        onSelectEmail={() => setShowEmailForm(true)}
                        googleButtonId={GOOGLE_BTN_ID}
                        loading={loading} // Changed from loading to false to always show content
                        googleProcessing={authProcessing}
                    />
                )}
                
                {authProcessing && (
                    <div className="absolute inset-0 bg-black/20 backdrop-blur-sm rounded-[32px] flex items-center justify-center z-50">
                        <i className="fa-solid fa-circle-notch fa-spin text-[#00c2ff] text-2xl"></i>
                    </div>
                )}
            </div>
        </div>
    );
};
