
import React from 'react';

const ArcReactor: React.FC<{ isActive: boolean }> = ({ isActive }) => {
  return (
    <div className="relative w-48 h-48 flex items-center justify-center">
      {/* Outer Ring */}
      <div className={`absolute inset-0 border-4 border-cyan-500/30 rounded-full animate-[spin_10s_linear_infinite]`}>
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-4 h-4 bg-cyan-400 rounded-full shadow-[0_0_15px_#00f2ff]"></div>
      </div>
      
      {/* Middle Ring */}
      <div className={`absolute inset-4 border-2 border-cyan-400/50 border-dashed rounded-full ${isActive ? 'animate-[spin_4s_linear_infinite_reverse]' : ''}`}></div>
      
      {/* Inner Glowing Core */}
      <div className={`relative w-24 h-24 rounded-full flex items-center justify-center bg-cyan-900/20 shadow-[inset_0_0_30px_rgba(0,242,255,0.5)] border border-cyan-400/80`}>
        <div className={`w-16 h-16 rounded-full bg-cyan-400/20 blur-md ${isActive ? 'animate-pulse' : ''}`}></div>
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-10 h-10 border-t-2 border-r-2 border-cyan-400 rounded-full animate-spin"></div>
        </div>
        <span className="text-[10px] font-bold text-cyan-400 mt-1 uppercase tracking-widest">Core</span>
      </div>

      {/* Hexagon Pattern Overlay */}
      <div className="absolute inset-0 pointer-events-none opacity-20">
         <svg width="100%" height="100%" viewBox="0 0 100 100">
            <path d="M50 0 L93.3 25 L93.3 75 L50 100 L6.7 75 L6.7 25 Z" fill="none" stroke="currentColor" strokeWidth="0.5" className="text-cyan-400"/>
         </svg>
      </div>
    </div>
  );
};

export default ArcReactor;
