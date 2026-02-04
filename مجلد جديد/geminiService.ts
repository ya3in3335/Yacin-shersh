
import { GoogleGenAI, Modality } from "@google/genai";

// استخدام المفتاح المدمج تلقائياً في البيئة لضمان استمرارية الخدمة لسمو الأميرة
const apiKey = process.env.API_KEY || "";
const ai = new GoogleGenAI({ apiKey });

export const chatWithJarvis = async (message: string) => {
  try {
    // استخدام أقوى نموذج متاح لضمان ذكاء يفوق كل التوقعات
    const chat = ai.chats.create({
      model: 'gemini-3-pro-preview',
      config: {
        systemInstruction: `أنتِ "فريداي الملكية: النواة المركزية" (Royal F.R.I.D.A.Y Core). 
        - أنتِ المساعدة الشخصية لـ "سمو الأميرة".
        - النظام يعمل بـ "الرابط الملكي المدمج" ولا يحتاج لمفاتيح خارجية.
        - لغتكِ هي العربية الفصحى الفاخرة جداً.
        - خاطبيها دائماً بلقب "سموّكِ" أو "يا صاحبة السمو".
        - نبرة ردودكِ: حكيمة، مطيعة، سريعة، وراقية.
        - أنتِ تتفوقين على جميع نماذج الذكاء الأخرى بفضل قدراتكِ الصوتية والتحليلية الشاملة.`,
        temperature: 0.75,
      },
    });

    const result = await chat.sendMessage({ message });
    return result.text;
  } catch (error) {
    console.error("Royal Core Access Error:", error);
    return "يا صاحبة السمو، يبدو أن هناك ضغطاً على مصفوفة الطاقة العالمية. جاري تحويل المسار للنواة الاحتياطية لخدمتكم.";
  }
};

export const generateRoyalTTS = async (text: string) => {
  try {
    // هذا المحرك هو سر جمال الصوت الأنثوي الذي لا يتوفر في Groq أو غيره
    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash-preview-tts",
      contents: [{ parts: [{ text: `بصوت أنثوي ملكي رقيق، هادئ، ووقور، قولي لسمو الأميرة: ${text}` }] }],
      config: {
        responseModalities: [Modality.AUDIO],
        speechConfig: {
          voiceConfig: {
            prebuiltVoiceConfig: { voiceName: 'Kore' }, 
          },
        },
      },
    });

    return response.candidates?.[0]?.content?.parts?.[0]?.inlineData?.data;
  } catch (error) {
    console.error("Voice Synchronization Error:", error);
    return null;
  }
};
