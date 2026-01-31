import { CATEGORIES } from '../data';
import SubcategoryTabs from './SubcategoryTabs';
import CommandGrid from './CommandGrid';

function MainContent({ 
  selectedCategory,
  selectedSubcategory,
  onSelectSubcategory,
  subcategories,
  subcategoryCounts,
  commands,
  searchQuery,
  onOpenMobileSidebar
}) {
  const category = CATEGORIES[selectedCategory];

  return (
    <main className="flex-1 p-4 lg:p-6 overflow-y-auto">
      {/* Mobile menu button */}
      <div className="lg:hidden mb-4">
        <button
          onClick={onOpenMobileSidebar}
          className="flex items-center gap-2 px-4 py-2 bg-gray-800 rounded-lg text-gray-300 hover:text-gray-100 hover:bg-gray-700 transition-colors"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
          <span>Categories</span>
        </button>
      </div>

      {/* Category Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <span className="text-3xl">{category?.icon}</span>
          <div>
            <h2 className="text-2xl font-bold text-gray-100">{category?.name}</h2>
            <p className="text-gray-400">{category?.description}</p>
          </div>
        </div>
        
        {searchQuery && (
          <div className="mt-3 flex items-center gap-2 text-sm text-gray-400">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <span>Showing results for "{searchQuery}"</span>
            <span className="text-gray-500">({commands.length} found)</span>
          </div>
        )}
      </div>

      {/* Subcategory Tabs */}
      <SubcategoryTabs
        subcategories={subcategories}
        selectedSubcategory={selectedSubcategory}
        onSelectSubcategory={onSelectSubcategory}
        subcategoryCounts={subcategoryCounts}
      />

      {/* Command Grid */}
      <CommandGrid 
        commands={commands} 
        searchQuery={searchQuery}
      />
    </main>
  );
}

export default MainContent;
