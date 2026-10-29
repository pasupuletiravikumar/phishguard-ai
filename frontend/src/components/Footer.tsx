import { Shield } from 'lucide-react';
import Link from 'next/link';

const footerLinks = [
  { label: 'About', href: '/about' },
  { label: 'Scanner', href: '/scanner' },
  { label: 'Dashboard', href: '/dashboard' },
];

export default function Footer() {
  const githubUrl = process.env.NEXT_PUBLIC_GITHUB_URL || 'https://github.com/pasupuletiravikumar/phishguard-ai';

  return (
    <footer className="border-t border-navy-700/50 bg-navy-900/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* Brand */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Shield className="h-6 w-6 text-cyan" />
              <span className="text-base font-bold text-white">
                Phish<span className="text-cyan">Guard</span> AI
              </span>
            </div>
            <p className="text-sm text-gray-500 max-w-xs">
              AI-powered phishing detection platform. Detect threats, protect identities, browse safely.
            </p>
          </div>

          {/* Links */}
          <div>
            <h4 className="text-sm font-semibold text-gray-300 mb-3">Navigation</h4>
            <ul className="space-y-2">
              {footerLinks.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-sm text-gray-500 hover:text-cyan transition-colors"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
              {githubUrl !== '#' && (
                <li>
                  <a
                    href={githubUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-gray-500 hover:text-cyan transition-colors"
                  >
                    GitHub
                  </a>
                </li>
              )}
            </ul>
          </div>

          {/* Disclaimer */}
          <div>
            <h4 className="text-sm font-semibold text-gray-300 mb-3">Disclaimer</h4>
            <p className="text-xs text-gray-500 leading-relaxed">
              PhishGuard AI provides preliminary security assessments for educational
              and research purposes. Results are not a guarantee that a URL or message
              is safe. Always exercise caution with suspicious content.
            </p>
          </div>
        </div>

        <div className="mt-8 pt-6 border-t border-navy-700/30 flex flex-col sm:flex-row justify-between items-center gap-2">
          <p className="text-xs text-gray-600">
            &copy; {new Date().getFullYear()} PhishGuard AI. Built for academic research.
          </p>
          <p className="text-xs text-gray-600">
            B.Tech CSE Cybersecurity Final Year Project
          </p>
        </div>
      </div>
    </footer>
  );
}
