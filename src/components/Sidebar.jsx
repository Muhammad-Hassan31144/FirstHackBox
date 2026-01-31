import { CATEGORIES } from '../data';

function Sidebar({ 
  selectedOS, 
  selectedCategory, 
  onSelectCategory, 
  categoryCounts,
  isMobileOpen,
  onCloseMobile 
}) {
  const categoryList = Object.entries(CATEGORIES);

  return (
    <>
      {/* Mobile overlay */}
      {isMobileOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={onCloseMobile}
        />
      )}
      
      {/* Sidebar */}
      <aside 
        className={`
          fixed lg:static inset-y-0 left-0 z-50 
          w-64 bg-gray-800 border-r border-gray-700
          transform transition-transform duration-300 ease-in-out
          lg:transform-none lg:transition-none
          ${isMobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
          overflow-y-auto
        `}
      >
        <div className="p-4">
          {/* Mobile close button */}
          <div className="lg:hidden flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-gray-100">Categories</h2>
            <button 
              onClick={onCloseMobile}
              className="p-2 text-gray-400 hover:text-gray-100"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Category navigation */}
          <nav className="space-y-1">
            {categoryList.map(([key, category]) => {
              const count = categoryCounts[key] || 0;
              const isSelected = selectedCategory === key;
              
              return (
                <button
                  key={key}
                  onClick={() => {
                    onSelectCategory(key);
                    onCloseMobile();
                  }}
                  className={`
                    w-full flex items-center justify-between px-3 py-2.5 rounded-lg
                    transition-all duration-200 text-left
                    ${isSelected 
                      ? 'bg-blue-600 text-white' 
                      : 'text-gray-300 hover:bg-gray-700 hover:text-gray-100'
                    }
                  `}
                >
                  <div className="flex items-center gap-3">
                    <span className="text-lg">{category.icon}</span>
                    <div>
                      <div className="font-medium text-sm">{category.name}</div>
                      <div className={`text-xs ${isSelected ? 'text-blue-200' : 'text-gray-500'}`}>
                        {category.description}
                      </div>
                    </div>
                  </div>
                  <span className={`
                    text-xs font-medium px-2 py-0.5 rounded-full
                    ${isSelected 
                      ? 'bg-blue-500 text-white' 
                      : 'bg-gray-700 text-gray-400'
                    }
                  `}>
                    {count}
                  </span>
                </button>
              );
            })}
          </nav>

          {/* Quick stats */}
          <div className="mt-6 pt-6 border-t border-gray-700">
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">
              Quick Stats
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-gray-700/50 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-gray-100">
                  {Object.values(categoryCounts).reduce((a, b) => a + b, 0)}
                </div>
                <div className="text-xs text-gray-400">Total Commands</div>
              </div>
              <div className="bg-gray-700/50 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-gray-100">
                  {categoryList.length}
                </div>
                <div className="text-xs text-gray-400">Categories</div>
              </div>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}

export default Sidebar;
