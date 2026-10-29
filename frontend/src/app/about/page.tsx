import {
  Shield,
  Brain,
  Code2,
  Database,
  AlertTriangle,
  BookOpen,
  Target,
  Layers,
} from 'lucide-react';

const techStack = [
  { category: 'Frontend', items: ['Next.js 14', 'React 18', 'TypeScript', 'Tailwind CSS', 'Recharts', 'Lucide Icons'] },
  { category: 'Backend', items: ['Python', 'FastAPI', 'Pydantic', 'Scikit-learn'] },
  { category: 'Database', items: ['SQLite (local)', 'Supabase PostgreSQL (optional)'] },
  { category: 'ML Pipeline', items: ['Random Forest Classifier', 'Joblib serialization', '16 URL features'] },
  { category: 'Testing', items: ['Pytest', 'HTTPX test client', '30+ automated tests'] },
];

const detectionMethods = [
  {
    icon: Target,
    title: 'Rule-Based Detection',
    description:
      'Comprehensive pattern matching across 20+ detection rules including IP host detection, typosquatting analysis, URL shortener identification, punycode/IDN homograph detection, suspicious keyword analysis, and Shannon entropy evaluation.',
  },
  {
    icon: Brain,
    title: 'Machine Learning Classification',
    description:
      'Random Forest classifier trained on 16 lexical and structural URL features. Provides phishing probability scores as supplementary evidence alongside rule-based findings.',
  },
  {
    icon: Layers,
    title: 'Probabilistic Risk Scoring',
    description:
      'Risk scores calculated using a probabilistic independent-risk union formula rather than simple summation. Severity anchoring ensures critical findings produce appropriately high scores. Transparent breakdown shows each contributing factor.',
  },
  {
    icon: AlertTriangle,
    title: 'Threat Intelligence Integration',
    description:
      'Optional integration with VirusTotal and Google Safe Browsing APIs for live reputation checking. Falls back gracefully to local analysis when API keys are not configured.',
  },
];

const limitations = [
  'ML model trained on a small curated dataset — perfect metrics reflect overfitting, not real-world performance.',
  'No live URL fetching or redirect following — analysis is based on URL structure only.',
  'No DNS resolution or WHOIS lookup performed.',
  'Email header analysis is based on pasted text, not direct mail server integration.',
  'Risk scores are heuristic assessments, not definitive security verdicts.',
  'This is an educational and research tool, not a replacement for enterprise security products.',
];

export default function AboutPage() {
  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Header */}
      <div className="mb-12">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-12 h-12 rounded-xl bg-cyan/10 flex items-center justify-center">
            <Shield className="h-6 w-6 text-cyan" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white">About PhishGuard AI</h1>
            <p className="text-gray-400">AI-Powered Phishing Detection Platform</p>
          </div>
        </div>
        <p className="text-gray-300 leading-relaxed max-w-3xl mt-4">
          PhishGuard AI is a cybersecurity platform designed to identify potentially
          malicious URLs, suspicious emails, phishing indicators, and social
          engineering attempts. It combines rule-based detection, URL structure
          analysis, email content analysis, and optional machine learning
          classification to provide explainable risk assessments.
        </p>
      </div>

      {/* Project Context */}
      <section className="card mb-8">
        <div className="flex items-center gap-2 mb-3">
          <BookOpen className="h-5 w-5 text-cyan" />
          <h2 className="text-xl font-semibold text-white">Project Context</h2>
        </div>
        <p className="text-gray-400 text-sm leading-relaxed">
          This project was developed as a final-year B.Tech Computer Science
          Engineering (Cybersecurity) project. It demonstrates practical knowledge
          of phishing detection, URL analysis, email security, machine learning,
          threat scoring, secure API development, and security reporting.
        </p>
      </section>

      {/* Detection Methodology */}
      <section className="mb-8">
        <h2 className="section-title mb-6">Detection Methodology</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {detectionMethods.map((method) => (
            <div key={method.title} className="card">
              <div className="flex items-center gap-2 mb-3">
                <method.icon className="h-5 w-5 text-cyan" />
                <h3 className="text-base font-semibold text-white">{method.title}</h3>
              </div>
              <p className="text-sm text-gray-400 leading-relaxed">
                {method.description}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Technology Stack */}
      <section className="mb-8">
        <div className="flex items-center gap-2 mb-6">
          <Code2 className="h-5 w-5 text-cyan" />
          <h2 className="section-title">Technology Stack</h2>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {techStack.map((group) => (
            <div key={group.category} className="card">
              <h3 className="text-sm font-semibold text-cyan mb-3">{group.category}</h3>
              <ul className="space-y-1.5">
                {group.items.map((item) => (
                  <li key={item} className="text-sm text-gray-400 flex items-center gap-2">
                    <span className="w-1 h-1 rounded-full bg-cyan/50" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      {/* Limitations */}
      <section className="mb-8">
        <div className="flex items-center gap-2 mb-6">
          <AlertTriangle className="h-5 w-5 text-amber-400" />
          <h2 className="section-title">Known Limitations</h2>
        </div>
        <div className="card border-amber-500/20">
          <ul className="space-y-3">
            {limitations.map((item, i) => (
              <li key={i} className="flex items-start gap-3 text-sm text-gray-400">
                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-amber-500/10 flex items-center justify-center text-xs text-amber-400 font-mono mt-0.5">
                  {i + 1}
                </span>
                {item}
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* Security Considerations */}
      <section>
        <div className="flex items-center gap-2 mb-6">
          <Database className="h-5 w-5 text-cyan" />
          <h2 className="section-title">Security Considerations</h2>
        </div>
        <div className="card">
          <ul className="space-y-2 text-sm text-gray-400">
            <li>• Submitted URLs are never fetched, followed, or downloaded by the application.</li>
            <li>• API endpoints enforce payload size limits and security headers.</li>
            <li>• CORS is configured to restrict cross-origin requests.</li>
            <li>• No user-submitted content is executed or rendered as active code.</li>
            <li>• Database credentials and API keys are kept server-side via environment variables.</li>
            <li>• Scan results are stored locally and are not shared with third parties.</li>
          </ul>
        </div>
      </section>
    </div>
  );
}
