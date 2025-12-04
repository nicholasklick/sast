
import React from 'react';

function VulnerableComponent({ userInput }) {
  // Vulnerable to XSS via dangerouslySetInnerHTML
  return <div dangerouslySetInnerHTML={{ __html: userInput }} />;
}

export default VulnerableComponent;
