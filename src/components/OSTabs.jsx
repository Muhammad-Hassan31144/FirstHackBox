function OSTabs({ selectedOS, onSelectOS }) {
  const osOptions = [
    { id: 'windows', label: 'Windows', icon: '🪟' },
    { id: 'linux', label: 'Linux', icon: '🐧' }
  ];

  return (
    <div className="bg-gray-800 border-b border-gray-700">
      <div className="max-w-full mx-auto px-4">
        <div className="flex gap-1">
          {osOptions.map((os) => (
            <button
              key={os.id}
              onClick={() => onSelectOS(os.id)}
              className={`
                flex items-center gap-2 px-6 py-3 text-sm font-medium rounded-t-lg
                transition-all duration-200 border-b-2
                ${selectedOS === os.id
                  ? 'bg-gray-900 text-gray-100 border-blue-500'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-750 border-transparent'
                }
              `}
            >
              <span className="text-lg">{os.icon}</span>
              <span>{os.label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

export default OSTabs;
