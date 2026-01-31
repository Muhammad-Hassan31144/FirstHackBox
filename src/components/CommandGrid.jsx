import CommandCard from './CommandCard';

function CommandGrid({ commands, searchQuery }) {
  if (commands.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <div className="text-6xl mb-4">🔍</div>
        <h3 className="text-xl font-semibold text-gray-300 mb-2">No commands found</h3>
        <p className="text-gray-500 max-w-md">
          Try adjusting your search query or selecting a different category or subcategory.
        </p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
      {commands.map((command) => (
        <CommandCard 
          key={command.id} 
          command={command} 
          searchQuery={searchQuery}
        />
      ))}
    </div>
  );
}

export default CommandGrid;
