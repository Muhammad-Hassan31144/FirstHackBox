/**
 * Search commands by query
 * @param {Array} commands - Array of command objects
 * @param {string} query - Search query string
 * @returns {Array} - Filtered commands matching the query
 */
export function searchCommands(commands, query) {
  if (!query || !query.trim()) {
    return commands;
  }

  const normalizedQuery = query.toLowerCase().trim();
  
  return commands.filter(cmd => {
    // Search in title
    if (cmd.title.toLowerCase().includes(normalizedQuery)) return true;
    
    // Search in description
    if (cmd.description.toLowerCase().includes(normalizedQuery)) return true;
    
    // Search in command syntax
    if (cmd.command.toLowerCase().includes(normalizedQuery)) return true;
    
    // Search in example
    if (cmd.example && cmd.example.toLowerCase().includes(normalizedQuery)) return true;
    
    // Search in tags
    if (cmd.tags.some(tag => tag.toLowerCase().includes(normalizedQuery))) return true;
    
    // Search in tools
    if (cmd.tools.some(tool => tool.toLowerCase().includes(normalizedQuery))) return true;
    
    return false;
  });
}

/**
 * Debounce function for search input
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} - Debounced function
 */
export function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * Highlight matching text in a string
 * @param {string} text - The text to search in
 * @param {string} query - The query to highlight
 * @returns {Array} - Array of text parts with match info
 */
export function getHighlightParts(text, query) {
  if (!query || !text) {
    return [{ text, isMatch: false }];
  }

  const regex = new RegExp(`(${escapeRegex(query)})`, 'gi');
  const parts = text.split(regex);
  
  return parts
    .filter(part => part.length > 0)
    .map(part => ({
      text: part,
      isMatch: part.toLowerCase() === query.toLowerCase()
    }));
}

/**
 * Escape special regex characters
 * @param {string} string - String to escape
 * @returns {string} - Escaped string
 */
function escapeRegex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
