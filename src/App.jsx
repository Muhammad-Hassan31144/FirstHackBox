import { useState, useMemo } from 'react';
import { Header, OSTabs, Sidebar, MainContent } from './components';
import { 
  allCommands, 
  CATEGORIES, 
  getSubcategoriesForCategory 
} from './data';

function App() {
  // State
  const [selectedOS, setSelectedOS] = useState('windows');
  const [selectedCategory, setSelectedCategory] = useState('awareness');
  const [selectedSubcategory, setSelectedSubcategory] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState(false);

  // Filter commands based on current state
  const filteredCommands = useMemo(() => {
    let commands = allCommands.filter(cmd => cmd.os === selectedOS);
    
    // Filter by category
    commands = commands.filter(cmd => cmd.category === selectedCategory);
    
    // Filter by subcategory if selected
    if (selectedSubcategory) {
      commands = commands.filter(cmd => cmd.subcategory === selectedSubcategory);
    }
    
    // Filter by search query
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      commands = commands.filter(cmd => 
        cmd.title.toLowerCase().includes(query) ||
        cmd.description.toLowerCase().includes(query) ||
        cmd.command.toLowerCase().includes(query) ||
        cmd.tags.some(tag => tag.toLowerCase().includes(query)) ||
        cmd.tools.some(tool => tool.toLowerCase().includes(query))
      );
    }
    
    return commands;
  }, [selectedOS, selectedCategory, selectedSubcategory, searchQuery]);

  // Get category counts for sidebar
  const categoryCounts = useMemo(() => {
    const counts = {};
    const osCommands = allCommands.filter(cmd => cmd.os === selectedOS);
    
    Object.keys(CATEGORIES).forEach(category => {
      let categoryCommands = osCommands.filter(cmd => cmd.category === category);
      
      // If searching, only count matching commands
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        categoryCommands = categoryCommands.filter(cmd => 
          cmd.title.toLowerCase().includes(query) ||
          cmd.description.toLowerCase().includes(query) ||
          cmd.command.toLowerCase().includes(query) ||
          cmd.tags.some(tag => tag.toLowerCase().includes(query)) ||
          cmd.tools.some(tool => tool.toLowerCase().includes(query))
        );
      }
      
      counts[category] = categoryCommands.length;
    });
    
    return counts;
  }, [selectedOS, searchQuery]);

  // Get available subcategories for current category
  const availableSubcategories = useMemo(() => {
    return getSubcategoriesForCategory(selectedOS, selectedCategory);
  }, [selectedOS, selectedCategory]);

  // Get subcategory counts
  const subcategoryCounts = useMemo(() => {
    const counts = {};
    let commands = allCommands.filter(
      cmd => cmd.os === selectedOS && cmd.category === selectedCategory
    );
    
    // If searching, only count matching commands
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      commands = commands.filter(cmd => 
        cmd.title.toLowerCase().includes(query) ||
        cmd.description.toLowerCase().includes(query) ||
        cmd.command.toLowerCase().includes(query) ||
        cmd.tags.some(tag => tag.toLowerCase().includes(query)) ||
        cmd.tools.some(tool => tool.toLowerCase().includes(query))
      );
    }
    
    availableSubcategories.forEach(sub => {
      counts[sub] = commands.filter(cmd => cmd.subcategory === sub).length;
    });
    
    return counts;
  }, [selectedOS, selectedCategory, searchQuery, availableSubcategories]);

  // Handlers
  const handleOSChange = (os) => {
    setSelectedOS(os);
    setSelectedSubcategory(null); // Reset subcategory when OS changes
  };

  const handleCategoryChange = (category) => {
    setSelectedCategory(category);
    setSelectedSubcategory(null); // Reset subcategory when category changes
  };

  const handleSearchChange = (query) => {
    setSearchQuery(query);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 flex flex-col">
      {/* Header */}
      <Header 
        searchQuery={searchQuery}
        onSearchChange={handleSearchChange}
      />

      {/* OS Tabs */}
      <OSTabs 
        selectedOS={selectedOS}
        onSelectOS={handleOSChange}
      />

      {/* Main Layout */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <Sidebar
          selectedOS={selectedOS}
          selectedCategory={selectedCategory}
          onSelectCategory={handleCategoryChange}
          categoryCounts={categoryCounts}
          isMobileOpen={isMobileSidebarOpen}
          onCloseMobile={() => setIsMobileSidebarOpen(false)}
        />

        {/* Main Content */}
        <MainContent
          selectedCategory={selectedCategory}
          selectedSubcategory={selectedSubcategory}
          onSelectSubcategory={setSelectedSubcategory}
          subcategories={availableSubcategories}
          subcategoryCounts={subcategoryCounts}
          commands={filteredCommands}
          searchQuery={searchQuery}
          onOpenMobileSidebar={() => setIsMobileSidebarOpen(true)}
        />
      </div>
    </div>
  );
}

export default App;
