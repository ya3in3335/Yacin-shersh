
export interface Message {
  id: string;
  role: 'user' | 'model';
  text: string;
  timestamp: Date;
}

export interface SystemStats {
  cpu: number;
  memory: number;
  network: number;
  temperature: number;
}
