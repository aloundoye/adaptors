// utils includes little builder functions

import _ from 'lodash';

const systemMap = {
  SmartCareID: 'http://moh.gov.et/fhir/hiv/identifier/SmartCareID',
  MRN: 'http://moh.gov.et/fhir/hiv/identifier/MRN',
  UAN: 'http://moh.gov.et/fhir/hiv/identifier/UAN',
};

// so what does this take?
export const mapSystems = obj => {
  if (Array.isArray(obj)) {
    return obj.map(mapSystems);
  }

  if (obj.system in systemMap) {
    return {
      ...obj,
      system: systemMap[obj.system],
    };
  }
  return obj;
};

export const setSystemMap = newMappings => {
  Object.assign(systemMap, newMappings);
};

// rather than code gen these with all their complexity,
// we can keep them in the library
// we can even unit test them if we want

// Create an identifier
// input can be a Full identifier, an Identifier with just a value, or a string value
// Note that if system is passed, it'll override
// (is this correct? This will force an input value to be mapped to the new system)
// Maybe the mapper can run some kind of conversion if neccessary?

// TODO I don't think the system is actually useful here
// Maybe it would be more useful to provide system mappings?
// ie UAN - > http://moh.gov.et/fhir/hiv/identifier/UAN
// and mapping code can add extra system mappings
// I like this
/**
 * Create an identifier
 * @public
 * @function
 */
export const identifier = (input, system) => {
  // If an array of inputs is passed in, map each element of the array
  // because it's very common to support a set of identifiers, rather than just one
  if (Array.isArray(input)) {
    return input.map(i => identifier(i, system));
  }

  if (input) {
    if (typeof input === 'string') {
      return mapSystems({
        value: input,
        system,
      });
    } else if (system) {
      return mapSystems({
        // Is system a default or override?
        // Probably a default?
        system,
        ...input,
      });
    } else {
      return mapSystems(input);
    }
  }
};

/**
 * Add an extension to a resource (or object)
 * @public
 * @function
 */
export const addExtension = (resource, url, value) => {
  const obj = {
    url: url,
  };

  if (value.coding) {
    obj.valueCodeableConcept = value;
  } else {
    obj.value = value;
  }
  // TODO we have to infer every value type here

  resource.extension ??= [];
  resource.extension.push(obj);
};

// TODO this should take an object and find the extension in object.extension
/**
 * Find an extension with a given url in some array
 * @public
 * @function
 */
export const findExtension = (obj, targetUrl, path) => {
  const result = obj.extension?.find(ext => ext.url === targetUrl);
  if (result && path) {
    return _.get(result, path);
  }
  return result;
};

// TODO should this also take display text?

/**
 * Create a coding
 * @public
 * @function
 */
export const coding = (code, system) => ({ code, system });

/**
 * Create a codeable concept. Codings can be coding objects or
 * [code, system] tuples
 * @public
 * @function
 */
export const concept = (text, ...codings) => {
  const result = {};
  let incomingCodings = codings;
  if (typeof text === 'string') {
    result.text = text;
  } else {
    incomingCodings = [text].concat(codings);
  }

  const c = [];
  for (const item of incomingCodings) {
    if (Array.isArray(item)) {
      c.push(coding(item[0], item[1]));
    } else {
      c.push(item);
    }
  }
  result.coding = c;

  return result;
};

// opts is { type, identifier, display}
// TODO if passed a full resource, return a ref to its id
// TODO: should the id be like `resource/id` ?
// I see the pattern a lot but I don't know if its formal
export const reference = (ref, opts) => {
  // if passed full reference, just return it
  if (ref.reference) {
    return ref;
  }

  const result = {};

  if (typeof ref === 'string') {
    result.reference = ref;
  }

  if (opts) {
    Object.assign(result, opts);
  }

  return result;
};

/** Convert an incoming value to one of a nummber of types based on the key, eg valueString, valueCodeableConcept */
export const composite = (object, key, value) => {
  const k = [key];


  if (value.coding) {
    k.push('CodeableConcept')
  } else if (value.reference) {
    k.push('Reference')
  }
  else if (typeof value === 'string') {
    k.push('String')
  }
  else if (typeof value === 'boolean') {
    k.push('Boolean')
  }
  else if (typeof value === 'number') {
    k.push('Integer')
  }
  // TODO: other data types need mapping

  if (k.length === 2) {
    const finalKey = k.join('')
    object[finalKey] = value;
  } else {
    console.warn(`WARNING: Failed to map ${key}: unrecognised data type (see utils.composite)`);
  }

}

