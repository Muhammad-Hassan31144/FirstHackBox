import { windowsCommands } from './windows-commands';
import { linuxCommands } from './linux-commands';
import { windowsLoggingCommands, linuxLoggingCommands } from './logging-evasion-commands';
import { CATEGORIES, SUBCATEGORIES, SUBCATEGORY_LABELS } from './categories';

// Merge all Windows commands (including logging evasion)
export const allWindowsCommands = [...windowsCommands, ...windowsLoggingCommands];

// Merge all Linux commands (including logging evasion)
export const allLinuxCommands = [...linuxCommands, ...linuxLoggingCommands];

export { CATEGORIES, SUBCATEGORIES, SUBCATEGORY_LABELS };

// Export original arrays for reference
export { windowsCommands, linuxCommands, windowsLoggingCommands, linuxLoggingCommands };

export const allCommands = [...allWindowsCommands, ...allLinuxCommands];

// Helper function to get commands by OS
export const getCommandsByOS = (os) => {
  return allCommands.filter(cmd => cmd.os === os);
};

// Helper function to get commands by category
export const getCommandsByCategory = (os, category) => {
  return allCommands.filter(cmd => cmd.os === os && cmd.category === category);
};

// Helper function to get available subcategories for a category
export const getSubcategoriesForCategory = (os, category) => {
  const commands = getCommandsByCategory(os, category);
  const subcategories = [...new Set(commands.map(cmd => cmd.subcategory))];
  return subcategories;
};

// Helper function to count commands per category
export const getCategoryCount = (os, category) => {
  return getCommandsByCategory(os, category).length;
};
