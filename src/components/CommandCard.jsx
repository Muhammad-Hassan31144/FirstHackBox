import { useState } from 'react';
import { SUBCATEGORY_LABELS } from '../data';

function CommandCard({ command, searchQuery }) {
  const [showExample, setShowExample] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  // Highlight matching text
  const highlightText = (text, query) => {
    if (!query || !text) return text;
    
    const parts = text.split(new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi'));
    return parts.map((part, i) => 
      part.toLowerCase() === query.toLowerCase() 
        ? <mark key={i} className="bg-yellow-500/30 text-yellow-200 rounded px-0.5">{part}</mark>
        : part
    );
  };

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 hover:border-gray-600 transition-all duration-200 overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <h3 className="font-semibold text-gray-100">
                {highlightText(command.title, searchQuery)}
              </h3>
              <span className="px-2 py-0.5 text-xs font-medium bg-gray-700 text-gray-300 rounded">
                {SUBCATEGORY_LABELS[command.subcategory] || command.subcategory}
              </span>
            </div>
            <p className="text-sm text-gray-400">
              {highlightText(command.description, searchQuery)}
            </p>
          </div>
        </div>
      </div>

      {/* Command Block */}
      <div className="relative group">
        <div className="bg-gray-950 p-4 font-mono text-sm overflow-x-auto">
          <code className="text-green-400 whitespace-pre-wrap break-all">
            {highlightText(command.command, searchQuery)}
          </code>
        </div>
        
        {/* Copy Button */}
        <button
          onClick={() => copyToClipboard(command.command)}
          className={`
            absolute top-2 right-2 px-3 py-1.5 rounded-md text-xs font-medium
            transition-all duration-200 flex items-center gap-1.5
            ${copied 
              ? 'bg-green-600 text-white' 
              : 'bg-gray-700 text-gray-300 opacity-0 group-hover:opacity-100 hover:bg-gray-600'
            }
          `}
        >
          {copied ? (
            <>
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              Copied!
            </>
          ) : (
            <>
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
              </svg>
              Copy
            </>
          )}
        </button>
      </div>

      {/* Example Section (collapsible) */}
      {command.example && (
        <div className="border-t border-gray-700">
          <button
            onClick={() => setShowExample(!showExample)}
            className="w-full px-4 py-2 flex items-center justify-between text-sm text-gray-400 hover:text-gray-200 hover:bg-gray-750 transition-colors"
          >
            <span>Example</span>
            <svg 
              className={`w-4 h-4 transition-transform duration-200 ${showExample ? 'rotate-180' : ''}`} 
              fill="none" 
              stroke="currentColor" 
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          
          {showExample && (
            <div className="relative group">
              <div className="bg-gray-900 p-4 font-mono text-sm border-t border-gray-700 overflow-x-auto">
                <code className="text-blue-400 whitespace-pre-wrap break-all">
                  {command.example}
                </code>
              </div>
              <button
                onClick={() => copyToClipboard(command.example)}
                className="absolute top-2 right-2 px-2 py-1 rounded text-xs bg-gray-700 text-gray-300 
                         opacity-0 group-hover:opacity-100 hover:bg-gray-600 transition-all duration-200"
              >
                Copy
              </button>
            </div>
          )}
        </div>
      )}

      {/* Tools & Tags Footer */}
      {(command.tools.length > 0 || command.tags.length > 0) && (
        <div className="px-4 py-3 border-t border-gray-700 flex flex-wrap gap-2">
          {/* Tools */}
          {command.tools.map((tool) => (
            <span 
              key={tool}
              className="px-2 py-1 text-xs font-medium bg-purple-900/50 text-purple-300 rounded-md border border-purple-700/50"
            >
              🔧 {tool}
            </span>
          ))}
          
          {/* Tags */}
          {command.tags.map((tag) => (
            <span 
              key={tag}
              className="px-2 py-1 text-xs bg-gray-700/50 text-gray-400 rounded-md"
            >
              #{highlightText(tag, searchQuery)}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export default CommandCard;
