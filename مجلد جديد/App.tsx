
import React, { useState, useEffect, useRef } from 'react';
import { Send, Crown, Volume2, Zap, ShieldCheck, Diamond, Sparkles } from 'lucide-react';
import { Message, SystemStats } from './types';
import { chatWithJarvis, generateRoyalTTS } from './geminiService';
import ArcReactor from './components/ArcReactor';
import StatsPanel from './components/StatsPanel';

function decodeBase64(base64: string) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

async function decodeAudioData(data: Uint8Array, ctx: AudioContext, sampleRate: number): Promise<AudioBuffer> {
  const dataInt16 = new Int16Array(data.buffer);
  const buffer = ctx.createBuffer(1, dataInt16.length, sampleRate);
  const channelData = buffer.getChannelData(0);
  for (let i = 0; i < dataInt16.length; i++) {
    channelData[i] = dataInt16[i] / 32768.0;
  }
  return buffer;
}

const App: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      role: 'model',
      text: 'سموّكِ، تم تفعيل "الرابط الملكي" مسبق الدفع. لا حاجة لأي مفاتيح خارجية؛ فالنظام يعمل بكامل طاقته لخدمتكم بصوتي الأنثوي الملكي. بماذا تأمرين سموّكِ؟',
      timestamp: new Date()
    }
  ]);
  const [input, setInput] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [stats, setStats] = useState<SystemStats>({ cpu: 5, memory: 28, network: 100, temperature: 36 });
  const [history, setHistory] = useState<{ cpu: any[], ram: any[] }>({ cpu: [], ram: [] });
  
  const scrollRef = useRef<HTMLDivElement>(null);
  const audioContextRef = useRef<AudioContext | null>(null);

  useEffect(() => {
    const interval = setInterval(() => {
      setStats(prev => ({
        cpu: Math.max(1, Math.min(10, prev.cpu + (Math.random() - 0.5) * 2)),
        memory: Math.max(15, Math.min(30, prev.memory + (Math.random() - 0.5) * 1)),
        network: 100,
        temperature: Math.max(32, Math.min(38, prev.temperature + (Math.random() - 0.5) * 1)),
      }));
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    setHistory(prev => ({
      cpu: [...prev.cpu.slice(-20), { value: stats.cpu }],
      ram: [...prev.ram.slice(-20), { value: stats.memory }],
    }));
  }, [stats]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const playRoyalAudio = async (base64Audio: string) => {
    try {
      if (!audioContextRef.current) {
        audioContextRef.current = new (window.AudioContext || (window as any).webkitAudioContext)({ sampleRate: 24000 });
      }
      const ctx = audioContextRef.current;
      const audioData = decodeBase64(base64Audio);
      const audioBuffer = await decodeAudioData(audioData, ctx, 24000);
      const source = ctx.createBufferSource();
      source.buffer = audioBuffer;
      source.connect(ctx.destination);
      source.start();
    } catch (err) {
      console.error("Audio Engine Error:", err);
    }
  };

  const handleSend = async () => {
    if (!input.trim() || isProcessing) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      text: input,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsProcessing(true);

    const responseText = await chatWithJarvis(input);
    
    const jarvisMessage: Message = {
      id: (Date.now() + 1).toString(),
      role: 'model',
      text: responseText || 'سموّكِ، حدث اضطراب في طبقة الأثير.',
      timestamp: new Date()
    };

    setMessages(prev => [...prev, jarvisMessage]);
    setIsProcessing(false);
    
    const base64Audio = await generateRoyalTTS(jarvisMessage.text);
    if (base64Audio) {
      await playRoyalAudio(base64Audio);
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] relative text-cyan-400 selection:bg-yellow-500/30 overflow-hidden font-['Noto_Kufi_Arabic']">
      {/* Background Ambience */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="hud-scanline opacity-10" />
        <div className="absolute inset-0 opacity-10 bg-[radial-gradient(circle_at_center,_#d4af37_0%,_transparent_70%)]" />
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-yellow-500/50 to-transparent" />
      </div>

      {/* Royal Header */}
      <header className="fixed top-0 left-0 right-0 h-16 border-b border-yellow-500/30 backdrop-blur-2xl z-50 flex items-center justify-between px-8 bg-black/80">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="p-1 rounded-full bg-yellow-500/10 border border-yellow-500/30">
              <Crown className="w-5 h-5 text-yellow-500 animate-pulse" />
            </div>
            <span className="text-xs font-bold tracking-[0.2em] text-yellow-500 uppercase">Royal Friday 3.0</span>
          </div>
          <div className="h-4 w-px bg-yellow-500/20" />
          <div className="flex items-center gap-2 text-green-400 drop-shadow-[0_0_8px_rgba(74,222,128,0.5)]">
            <ShieldCheck className="w-4 h-4" />
            <span className="text-[9px] font-bold uppercase tracking-widest">Pre-Authorized Access: ACTIVE</span>
          </div>
        </div>
        
        <div className="flex items-center gap-2">
          <Diamond className="w-4 h-4 text-yellow-500 animate-bounce" />
          <h1 className="text-xl font-bold tracking-[0.5em] uppercase text-yellow-500 italic drop-shadow-lg">PALACE HUD</h1>
          <Diamond className="w-4 h-4 text-yellow-500 animate-bounce" />
        </div>
        
        <div className="flex items-center gap-4">
          <div className="text-right border-r border-yellow-500/20 pr-4">
            <div className="text-[9px] opacity-60 text-yellow-500 font-bold uppercase tracking-tighter">Imperial Time</div>
            <div className="text-sm font-mono text-yellow-100">{new Date().toLocaleTimeString()}</div>
          </div>
          <Sparkles className="w-5 h-5 text-yellow-500/50" />
        </div>
      </header>

      <main className="pt-20 pb-12 h-screen flex gap-4 p-4 overflow-hidden relative z-10">
        {/* Left Stats Side */}
        <aside className="hidden lg:flex flex-col gap-4">
          <StatsPanel title="CPU" stats={stats} history={history.cpu} color="#d4af37" />
          <StatsPanel title="RAM" stats={stats} history={history.ram} color="#d4af37" />
          <div className="flex-1 bg-black/60 border border-yellow-500/20 rounded-lg p-4 backdrop-blur-md flex flex-col shadow-inner">
            <div className="flex items-center gap-2 mb-4 border-b border-yellow-500/20 pb-2">
              <Volume2 className="w-4 h-4 text-yellow-500" />
              <span className="text-[10px] uppercase font-bold tracking-widest text-yellow-500">Royal Audio Core</span>
            </div>
            <div className="flex-1 font-mono text-[9px] opacity-80 space-y-2 text-cyan-100">
              <div className="flex justify-between"><span>Engine:</span> <span className="text-yellow-500">Gemini Neural</span></div>
              <div className="flex justify-between"><span>Voice ID:</span> <span className="text-yellow-500">Kore (Female)</span></div>
              <div className="flex justify-between"><span>Status:</span> <span className="text-green-500">Online</span></div>
              <div className="mt-4 p-2 bg-yellow-500/5 border border-yellow-500/10 rounded italic text-[8px]">
                "نظام جيميناي مدمج لخدمتكم يا سموّكِ."
              </div>
            </div>
          </div>
        </aside>

        {/* Center Arc Reactor */}
        <section className="flex-1 flex flex-col items-center justify-center relative">
          <div className="relative z-20">
            <ArcReactor isActive={isProcessing} />
          </div>
          {/* Decorative Rings */}
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] border border-yellow-500/5 rounded-full animate-[spin_20s_linear_infinite]" />
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[550px] h-[550px] border border-cyan-500/5 rounded-full animate-[spin_30s_linear_infinite_reverse]" />
        </section>

        {/* Right Chat Side */}
        <section className="w-full md:w-[450px] flex flex-col gap-4 bg-black/80 border border-yellow-500/30 rounded-xl backdrop-blur-3xl overflow-hidden shadow-[0_0_50px_rgba(212,175,55,0.15)] border-t-yellow-500/50">
          <div className="p-4 border-b border-yellow-500/20 bg-gradient-to-r from-yellow-500/10 to-transparent flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Zap className="w-3 h-3 text-yellow-500" />
              <span className="text-[10px] font-bold tracking-widest uppercase text-yellow-500">Command Interface</span>
            </div>
            <div className="flex gap-1">
               <div className="w-1.5 h-1.5 rounded-full bg-yellow-500 shadow-[0_0_8px_#d4af37]" />
               <div className="w-1.5 h-1.5 rounded-full bg-yellow-500/30" />
               <div className="w-1.5 h-1.5 rounded-full bg-yellow-500/10" />
            </div>
          </div>

          <div ref={scrollRef} className="flex-1 overflow-y-auto p-6 space-y-8 scrollbar-hide">
            {messages.map((msg) => (
              <div key={msg.id} className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                <div className={`text-[8px] uppercase mb-2 tracking-[0.4em] font-bold ${msg.role === 'user' ? 'text-cyan-400' : 'text-yellow-500'}`}>
                  {msg.role === 'user' ? 'Highness' : 'Royal Friday'}
                </div>
                <div className={`max-w-[90%] p-5 rounded-2xl relative shadow-xl ${
                  msg.role === 'user' 
                  ? 'bg-cyan-900/20 border border-cyan-500/30 text-cyan-50 rounded-tr-none' 
                  : 'bg-yellow-900/10 border border-yellow-500/30 text-yellow-50 rounded-tl-none border-l-4'
                }`}>
                   <p className="text-sm leading-relaxed italic font-light">{msg.text}</p>
                   <div className="mt-2 text-[7px] opacity-30 text-right">
                     {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                   </div>
                </div>
              </div>
            ))}
            {isProcessing && (
              <div className="flex items-center gap-2 text-yellow-500/50 text-[10px] animate-pulse">
                <Sparkles className="w-3 h-3" />
                <span>جاري معالجة الأمر الملكي...</span>
              </div>
            )}
          </div>

          <div className="p-6 border-t border-yellow-500/20 bg-black/40">
            <div className="relative group">
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSend()}
                placeholder="بماذا تأمرين يا سموّكِ؟"
                className="w-full bg-black/60 border border-yellow-500/20 p-4 pr-14 rounded-xl text-sm focus:outline-none focus:border-yellow-500 focus:ring-1 focus:ring-yellow-500/50 transition-all placeholder:text-yellow-500/20 text-yellow-100 shadow-inner"
              />
              <button 
                onClick={handleSend} 
                disabled={isProcessing} 
                className="absolute right-3 top-1/2 -translate-y-1/2 p-2.5 bg-yellow-500 text-black rounded-lg hover:bg-yellow-400 hover:scale-105 transition-all disabled:opacity-30 disabled:grayscale"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </section>
      </main>

      {/* Footer Status */}
      <footer className="fixed bottom-0 left-0 right-0 h-10 border-t border-yellow-500/10 bg-black/90 flex items-center px-8 justify-between z-50 backdrop-blur-md">
        <div className="flex gap-10 items-center">
          <div className="flex items-center gap-2 text-yellow-500/40">
            <div className="w-1 h-1 rounded-full bg-yellow-500 animate-ping" />
            <span className="text-[8px] font-bold tracking-[0.5em] uppercase">Neural Link: Pre-Authorized</span>
          </div>
          <div className="text-[8px] text-cyan-500/40 font-bold uppercase tracking-widest hidden md:block">
            Safety Protocol: Level Alpha 1
          </div>
        </div>
        <div className="text-[8px] text-yellow-500/20 italic">
          &copy; 2025 Royal Artificial Intelligence Command
        </div>
      </footer>
    </div>
  );
};

export default App;
