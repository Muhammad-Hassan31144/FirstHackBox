import { SUBCATEGORY_LABELS } from '../data';

function SubcategoryTabs({ 
  subcategories, 
  selectedSubcategory, 
  onSelectSubcategory,
  subcategoryCounts 
}) {
  if (subcategories.length <= 1) {
    return null;
  }

  return (
    <div className="flex flex-wrap gap-2 mb-6">
      <button
        onClick={() => onSelectSubcategory(null)}
        className={`
          px-4 py-2 text-sm font-medium rounded-lg transition-all duration-200
          ${selectedSubcategory === null
            ? 'bg-blue-600 text-white'
            : 'bg-gray-700 text-gray-300 hover:bg-gray-600 hover:text-gray-100'
          }
        `}
      >
        All
        <span className="ml-2 text-xs opacity-75">
          ({Object.values(subcategoryCounts).reduce((a, b) => a + b, 0)})
        </span>
      </button>
      
      {subcategories.map((sub) => (
        <button
          key={sub}
          onClick={() => onSelectSubcategory(sub)}
          className={`
            px-4 py-2 text-sm font-medium rounded-lg transition-all duration-200
            ${selectedSubcategory === sub
              ? 'bg-blue-600 text-white'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600 hover:text-gray-100'
            }
          `}
        >
          {SUBCATEGORY_LABELS[sub] || sub}
          <span className="ml-2 text-xs opacity-75">
            ({subcategoryCounts[sub] || 0})
          </span>
        </button>
      ))}
    </div>
  );
}

export default SubcategoryTabs;
