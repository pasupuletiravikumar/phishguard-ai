import Link from 'next/link';
import {
  Shield,
  Search,
  Mail,
  Brain,
  BarChart3,
  FileText,
  History,
  ArrowRight,
  AlertTriangle,
  CheckCircle2,
  Zap,
  Eye,
} from 'lucide-react';

const features = [
  {
    icon: Search,
    title: 'URL Threat Analysis',
    description:
      'Deep URL structure analysis detects IP hosts, typosquatting, suspicious encoding, shorteners, and lookalike domains.',
  },
  {
    icon: Mail,
    title: 'Email Phishing Detection',
    description:
      'Identifies urgency tactics, credential harvesting, sender spoofing, and suspicious links in email content.',
  },
  {
    icon: Brain,
    title: 'AI-Assisted Classification',
    description:
      'Optional ML model trained on URL features provides phishing probability alongside rule-based analysis.',
  },
  {
    icon: Eye,
    title: 'Explainable Risk Scoring',
    description:
      'Transparent 0–100 risk scores with breakdown by finding severity, individual evidence, and confidence levels.',
  },
  {
    icon: FileText,
    title: 'Security Reports',
    description:
      'Export detailed scan reports in JSON or HTML format for documentation, incident response, or compliance.',
  },
  {
    icon: History,
    title: 'Scan History & Analytics',
    description:
      'Track all scans over time, filter by severity or type, and view aggregated threat analytics dashboards.',
  },
];

const steps = [
  {
    num: '01',
    icon: AlertTriangle,
    title: 'Submit',
    description: 'Paste a suspicious URL, email content, or chat message for analysis.',
  },
  {
    num: '02',
    icon: Zap,
    title: 'Analyze',
    description: 'Engine evaluates structure, patterns, and indicators against detection rules.',
  },
  {
    num: '03',
    icon: BarChart3,
    title: 'Review',
    description: 'Examine the risk score, individual findings, evidence, and severity breakdown.',
  },
  {
    num: '04',
    icon: CheckCircle2,
    title: 'Act',
    description: 'Follow recommended security actions and export reports for documentation.',
  },
];

export default function HomePage() {
  return (
    <div>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-cyan/5 via-transparent to-transparent" />
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-24 sm:pt-28 sm:pb-32">
          <div className="text-center max-w-3xl mx-auto">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-cyan/10 border border-cyan/20 text-cyan text-sm font-medium mb-6">
              <Shield className="h-4 w-4" />
              AI-Powered Threat Detection
            </div>
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-white tracking-tight leading-tight">
              Detect Phishing Before{' '}
              <span className="text-gradient">It Becomes a Threat</span>
            </h1>
            <p className="mt-6 text-lg text-gray-400 max-w-2xl mx-auto leading-relaxed">
              Analyze suspicious URLs, emails, and messages using security rules
              and machine learning-assisted threat detection. Get explainable risk
              scores and actionable recommendations.
            </p>
            <div className="mt-8 flex flex-col sm:flex-row gap-4 justify-center">
              <Link href="/scanner" className="btn-primary text-base">
                <Search className="h-5 w-5" />
                Analyze a Threat
              </Link>
              <a href="#features" className="btn-secondary text-base">
                Explore Features
                <ArrowRight className="h-4 w-4" />
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-20 sm:py-24">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-14">
            <h2 className="text-3xl font-bold text-white">
              Comprehensive Threat Detection
            </h2>
            <p className="mt-3 text-gray-400 max-w-xl mx-auto">
              Multiple detection engines work together to identify phishing
              indicators and generate clear security assessments.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature) => (
              <div key={feature.title} className="card-hover group">
                <div className="w-11 h-11 rounded-xl bg-cyan/10 flex items-center justify-center mb-4 group-hover:bg-cyan/15 transition-colors">
                  <feature.icon className="h-5 w-5 text-cyan" />
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">
                  {feature.title}
                </h3>
                <p className="text-sm text-gray-400 leading-relaxed">
                  {feature.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-20 bg-navy-900/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-14">
            <h2 className="text-3xl font-bold text-white">How It Works</h2>
            <p className="mt-3 text-gray-400">
              Four simple steps to analyze potential threats.
            </p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
            {steps.map((step) => (
              <div key={step.num} className="relative text-center">
                <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-navy-800 border border-navy-600/30 mb-4">
                  <step.icon className="h-6 w-6 text-cyan" />
                </div>
                <span className="block text-xs font-mono text-cyan/60 mb-1">
                  Step {step.num}
                </span>
                <h3 className="text-lg font-semibold text-white mb-2">
                  {step.title}
                </h3>
                <p className="text-sm text-gray-400">{step.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl font-bold text-white mb-4">
            Ready to Detect Threats?
          </h2>
          <p className="text-gray-400 mb-8 max-w-xl mx-auto">
            Start analyzing suspicious URLs, emails, and messages now. No account required for local analysis.
          </p>
          <Link href="/scanner" className="btn-primary text-base">
            <Shield className="h-5 w-5" />
            Launch Scanner
          </Link>
        </div>
      </section>

      {/* Disclaimer */}
      <section className="py-8 border-t border-navy-700/30">
        <div className="max-w-3xl mx-auto px-4 text-center">
          <p className="text-xs text-gray-600">
            <strong className="text-gray-500">Security Disclaimer:</strong>{' '}
            PhishGuard AI provides preliminary security assessments for
            educational and research purposes. Results are not a guarantee that
            a URL or message is safe. Always exercise caution with suspicious
            content and verify through additional sources.
          </p>
        </div>
      </section>
    </div>
  );
}
