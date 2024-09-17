import { expect } from 'chai';

// Note that we test against the build here
import * as builders from '../src/builders';
import * as util from '../src/Utils';
import output from './fixtures/output';
import input from './fixtures/input';

import fixtures from './fixtures';


// trying to organise
describe.only('Everything', () => {

  it('should map Patient', () => {
    const input = fixtures.cdr.patient;

    // set system mappings - identifier should use this automagically
    util.setSystemMap({
      'http://cdr.aacahb.gov.et/SmartCareID':
        'http://moh.gov.et/fhir/hiv/identifier/SmartCareID',
      'http://cdr.aacahb.gov.et/MRN':
        'http://moh.gov.et/fhir/hiv/identifier/MRN',
      'http://cdr.aacahb.gov.et/UAN':
        'http://moh.gov.et/fhir/hiv/identifier/UAN',
    });

    // address mapping is a bit painful right now
    // but I think we can get this working from strings automatically
    const mapAddress = a => {
      if (/rural/i.test(a.text)) {
        const { text, ...address } = a;
        return {
          ...address,
          residentialType: util.concept(
            'Rural',
            util.coding('224804009', 'http://snomed.info/sct')
          ),
        };
      }
      return a;
    };

    const religion = util.findExtension(
      input,
      'http://hl7.org/fhir/StructureDefinition/patient-religion'
    ).valueCodeableConcept.coding[0];

    const result = builders.patient('patient', {
      id: input.id,
      religion: util.concept(
        religion.display,
        util.coding(
          religion.code,
          'http://terminology.hl7.org/CodeSystem/v3-ReligiousAffiliation'
        )
      ),
      identifier: input.identifier,
      name: input.name,
      telecom: input.telecom,
      gender: input.gender,
      birthDate: input.birthDate,
      maritalStatus: input.maritalStatus,
      managingOrganization: input.managingOrganization,
      address: input.address.map(mapAddress),
    });

    // console.log(result);

    expect(result).to.eql(fixtures.ndr.patient);
  });

  it.skip('should match Related Person', () => {

  })

  it('should map Observation (highest education)', () => {
    const input = fixtures.cdr.patient;

    const ext = util.findExtension(input, "http://cdr.aacahb.gov.et/EducationalLevel")

    const result = builders.observation('highest-education-observation', {
      status: input.status ?? 'final',
      effectiveDateTime: input.period?.start,
      value: ext.valueString,
      subject: input.id,
    })

    expect(result).to.eql(fixtures.ndr.observationEducation);
  })

  it('should map Observation (patient occupation)', () => {
    const input = fixtures.cdr.patient;

    const ext = util.findExtension(
      input,
      'http://cdr.aacahb.gov.et/Occupation'
    );

    const result = builders.observation('patient-occupation-observation', {
      status: input.status ?? 'final',
      effectiveDateTime: input.period?.start,
      value: util.concept(ext.valueString),
      subject: input.id,
    })

    expect(result).to.eql(fixtures.ndr.observationOccupation);
  })

  it('should map Observation (target population)', () => {
    const input = fixtures.cdr.patient;

    const ext = util.findExtension(
      input,
      'http://cdr.aacahb.gov.et/TargetPopulationGroup'
    );

    const result = builders.observation('target-population-observation', {
      status: input.status ?? 'final',
      effectiveDateTime: input.period?.start,
      value: ext.valueString,
      subject: input.id,
    })

    expect(result).to.eql(fixtures.ndr.observationPopulation);
  })

  // this fails on teh system map for coding
  it.skip('should map Encounter (target-facility-encounter)', () => {
    const input = fixtures.cdr.encounter;

    util.setSystemMap({
      'http://cdr.aacahb.gov.et/Encounter':
        'http://moh.gov.et/fhir/hiv/identifier/encounter',
      'http://terminology.hl7.org/CodeSystem/service-type':
        'http://moh.gov.et/fhir/hiv/CodeSystem/encounter-service-type-code-system'
    });

    const visitType = util.findExtension(
      input,
      'http://cdr.aacahb.gov.et/visit-type'
    );

    const result = builders.encounter('target-facility-encounter', {
      id: input.id,
      status: input.status,
      class: input.class,
      identifier: input.identifier,
      // TODO I'm not sure how these map?
      serviceType: input.serviceType[0],
      period: input.period,
      subject: input.subject,
      // TODO why is this automated wrong?
      // is the test data wrong?
      serviceProvider: input.serviceProvider,

      // TODO this won't map the system properly right now
      // because we don't handle codeable concepts very smartly
      serviceType: {
        coding: input.serviceType.coding.slice(0, 1),
      },
      type: input.type,
      // visitType: visitType,
    });

    // Handle the visit type extension manually
    util.addExtension(
      result.type[0],
      'http://moh.gov.et/fhir/hiv/StructureDefinition/encounter-visit-type',
      util.concept([
        visitType.valueString,
        'http://moh.gov.et/fhir/hiv/CodeSystem/encounter-visit-type-code-system',
      ])
    ),
      console.log(result);

    expect(result).to.eql(fixtures.ndr.encounter);
  })

  // TODO I don't really have an example. I don't think it's much different though?
  it.skip('should map Encounter (outside-target-facility)', () => {});

  it('should map Medication Dispense - ARV', () => {
    const input = fixtures.cdr.medicationDispense;

    // Try and find a concept or reference in the  source to define the medication
    let ref;
    if (input.medicationCodeableConcept) {
      ref = input.medicationCodeableConcept.coding.find(({ system }) => system === 'http://cdr.aacahb.gov.et/hiv-regimen-codes')
      if (ref) {
        ref = ref.code;
      }
    } else if (input.reference) {
      ref = input.reference;
    }

    const handover = util.findExtension(input, 'http://cdr.aacahb.gov.et/dose-end-date')

    const result = builders.medicationDispense('arv-medication-dispense', {
      id: input.id,
      status: input.status,
      subject: input.subject,
      context: input.context,
      quantity: input.quantity,
      daysSupply: input.daysSupply,
      whenHandedOver: handover.valueDateTime,

      // TODO: need to support reference as a reference or codeable concept
      // also I don't see reference on the incoming data example? is it context.reference?
      medication: ref,


      // TODO this should refer to the MedicationRequest created
      // Do we know what that is?
      //authorizingPrescription: {}
    })

    expect(result).to.eql(fixtures.ndr.medicationDispense)
  })

  // TODO: array issue on Category
  // TODO: handle activity (as array of Backbone Elements)
  it.skip('should map CarePlan - ARV Treatment', () => {
    const input = fixtures.cdr.careplan;


    const result = builders.carePlan('art-follow-up-careplan', {
      id: input.id,
      status: input.status,
      intent: input.intent,
      created: input.created,
      reference: input.reference,
      subject: input.subject,
      encounter: input.encounter,

      // TODO how do we map activity?
      // need to handle backbone elements properly
    })

    // console.log(JSON.stringify(result, null, 2))
    
    // TODO category needs to be an array
    expect(result).to.eql(fixtures.ndr.careplan)
  })

  it('should map MedicationRequest - ARV', () => {
    // for this to work we need a set of CDR resources
    const dispense = fixtures.cdr.medicationDispense;
    const request = fixtures.cdr.medicationRequest;
    const plan = fixtures.cdr.careplan;
    const medication = fixtures.cdr.medication;

    const result = builders.medicationRequest('arv-medication-request', {
      // id: TODO shoudl we generate ids?

      // TODO: we should be able to pass a string here and the adaptor just handles it
      medication: util.reference(medication.id),
      
      // TODO this should just be `reason` (which accepts a reference)
      // TODO dispense.statusReasonCodeableConcept must be converted to an observrtion and referenced here
      reasonReference: util.reference('observartion/arv-regimen-changed-observation'),

      basedOn: util.reference(plan.id),
      
      // TODO this one isn't mapping at all
      // should just take a simple assignment?
      dispenseRequest: {
        quanity: dispense.quantity
      },

      status: 'completed', // hard-coded
      intent: 'order', // hard-coded

      // TODO is this right - the identifier comes from the request? spreadsheet isn't clear
      identifier: request.identifier,

      doNotPerform: true, // where does this map from?

      // TODO I should be able to pass a whole resource into reference and it'll ref the id
      subject: util.reference(dispense.subject),
      encounter: util.reference(dispense.context),

      // TODO where do I map this from?
      // authoredOn: 
    })

    expect(result).to.eql(fixtures.ndr.medicationRequest)
  });

  it('should map Medication - Represents an ARV Regimen', () => {
    const input = fixtures.cdr.medication;

    const [coding] = input.form.coding;

    const result = builders.medication('arv-regimen-medication', {

      id: input.id,

      // Not sure how strict to be on mapping here?
      // First we need to map the system and coding: looks like
      // NDR uses a fixed system ofhttp://cdr.aacahb.gov.et/hiv-regimen-codes I think?
      // (seems cosmetic)
      code: util.concept(coding.display, [coding.code, coding.system])

    })

    expect(result).to.eql(fixtures.ndr.medication)
  })

  // TODO: category confusion again - array or object?
  // TODO: I can't work out what I'm mapping value to
  it.skip('should map Observation - ART Followup Status', () => {
    const input = fixtures.cdr.medicationDispense;

    // hmm, I've taken this from the sheet but it doesn't feel right
    const ext = util.findExtension(input, 'http://cdr.aacahb.gov.et/medication-stopped-reason')

    const result = builders.observation('art-followup-status-observation', {
      // id: ??
      status: "final",
      subject: input.subject,
      encounter: input.context,
      
      // This is what the  spec says...
      // but I think I need to FIND the reference and pull the values out of it
      // effectiveDateTime: input.context?.reference?.period?.start,
      // // TODO this is not mapped yet (datetime I think)
      // effectivePeriod: input.context?.reference?.period,

      // TODO hard-coding these values for now
      effectiveDateTime: "2024-01-25",

      
      // TODO this won't do anything in the test
      value: ext && util.concept(ext)
    
    })

    expect(result).to.eql(fixtures.ndr.observationFollowup)
  })

  // TODO This isnt' a good test - values are missing and data is handwritten
  it('should map Observation - ARV Regimen Change', () => {
    const input = fixtures.cdr.medicationDispense;
    // this is a fake encounter, referenced by input.context
    const encounter =  {
      id: 'Encounter/e84781ed-5f02-40ac-8c97-e7280fb153e3',
      period: {
        start:  "2024-01-25",
        end:  "2024-01-25",
      },
      serviceProvider: {
        reference: 'abc'
      }
    }

    const result = builders.observation('arv-regimen-changed-observation', {
      status: 'final',
      subject: input.subject,
      encounter: input.context,

      effectiveDateTime: encounter.period.start,
      // TODO I don't think this maps to effectivePeriod
      // effective: encounter.period

      performer: encounter.serviceProvider

      // TODO again. I'm not sure where value is coming from
      // value:
      // hasMember

    })

    // console.log(JSON.stringify(result, null, 2))

    expect(result).to.eql(fixtures.ndr.observationRegimenChanged)
  })

  it('should map Observation - ARV Regimen Reason', () => {
    const input = fixtures.cdr.medicationDispense;

    // fake encounter for more plausible mapping
    const encounter =  {
      id: 'Encounter/e84781ed-5f02-40ac-8c97-e7280fb153e3',
      period: {
        start:  "2024-01-25",
        end:  "2024-01-25",
      },
      serviceProvider: {
        reference: 'abc'
      }
    }

    // TODO don't have data for this, so fake it. But this doesn't feel right to me
    let reason = util.findExtension(input, 'http://cdr.aacahb.gov.et/switch-reason')
    if (!reason) {
      reason = {
        display: "Virologic-Failure",
        code: "1234",
        url: "http://cdr.aacahb.gov.et/switch-reason"
      }
    }

    // TODO this mapping is super sketchy
    // It's OK for this test but how will we handle this in mapping code?
    const value = util.concept(reason.display, ["http://loinc.org", reason.code /*wrong code*/])

    // TO the value concept, we add an extension whose value is itself a concept
    // confusing
    // again, I don't know where values are mapping from here
    util.addExtension(
      value,
      "http://moh.gov.et/fhir/hiv/StructureDefinition/cd4-vl-classification-for-treatment-failure",
      util.concept([
        'http://moh.gov.et/fhir/hiv/CodeSystem/cd4-vl-classification-for-treatment-failure-code-system',
        reason.code
      ]))

    
    const result = builders.observation('arv-regimen-change-reason-observation', {
      status: 'final',
      value,
      subject: input.subject,
      encounter: input.context,
      effectiveDateTime: encounter.period.start,
      performer: encounter.serviceProvider
    });
    
    expect(result).to.eql(fixtures.ndr.observationRegimenChangedReason)
  });

  it('should map ARV Regimen Category Type', () => {
    const input = fixtures.cdr.medicationDispense;

    // fake encounter for more plausible mapping
    const encounter =  {
      id: 'Encounter/e84781ed-5f02-40ac-8c97-e7280fb153e3',
      period: {
        start:  "2024-01-25",
        end:  "2024-01-25",
      },
      serviceProvider: {
        reference: 'abc'
      }
    }

    // TODO this should be mapped out of extensions
    const switchType = {
      valueString: "abc" // TODO plausible value?
    }

    const result = builders.observation('arv-change-category-type-observation', {
      status: 'final',
      subject: input.subject,
      encounter: input.context,
      effectiveDateTime: encounter.period.start,
      performer: encounter.serviceProvider,
      
      value: switchType.valueString
    });
    console.log(JSON.stringify(result, null, 2))
    expect(result).to.eql(fixtures.ndr.observationRegimenChangedReason)
  })

  // TODO no data for this one again, but it's a straightforward operation
  it.skip('should map Observation - Reason HIV Treatment Stopped', () => {

  })

  it.only('should map Medication Administration - ARV', () => {
    const dispense = fixtures.cdr.medicationDispense;
    const request = fixtures.cdr.medicationRequest;

    const encounter =  {
      id: 'Encounter/e84781ed-5f02-40ac-8c97-e7280fb153e3',
      period: {
        start:  "2024-01-25",
        end:  "2024-01-25",
      },
      serviceProvider: {
        reference: 'abc'
      }
    }

    const result = builders.medicationAdministration('arv-medication-administration', {
      // id
      status: 'completed',
      medication: dispense.medication,
      subject: dispense.subject,
      encounter: dispense.context,
      effectivePeriod: encounter.period,
      request: util.reference(request.id)

    })

    console.log(JSON.stringify(result, null, 2))

    expect(result).to.eql(fixtures.ndr.medicationAdmin)
  })

});

describe('General', () => {
  it('should not try to map a value that is undefined', () => {
    const result = builders.patient('patient', {
      gender: undefined,
    });

    expect('gender' in result).be.false;
  });

  it('should not try to map a value that is null', () => {
    const result = builders.patient('patient', {
      gender: undefined,
    });

    expect('gender' in result).be.false;
  });

  it('should try to map a value that is 0', () => {
    const result = builders.patient('patient', {
      gender: 0,
    });

    expect(result.gender).to.equal(0);
  });

  it('should map a Reference string', () => {
    const result = builders.observation('patient-occupation-observation', {
      subject: 'patient/123',
    });

    expect(result.subject).to.eql({
      reference: 'patient/123',
    });
  });
});

// TODO: I want all these mapping types declared in the code somewhere
// https://docs.google.com/spreadsheets/d/1CYYhDy25Uc4-9fwtj7HHTPzBxIW480H6rRqP0ZKxYXI/edit?gid=1486293516#gid=1486293516
// Just for discoverablilty

describe('Encounter', () => {
  it.skip('should convert CDR to NDR', () => {
    const input = fixtures.cdr.encounter;

    util.setSystemMap({
      'http://cdr.aacahb.gov.et/Encounter':
        'http://moh.gov.et/fhir/hiv/identifier/encounter',
    });

    const visitType = util.findExtension(
      input,
      'http://cdr.aacahb.gov.et/visit-type'
    );

    const result = builders.encounter('target-facility-encounter', {
      id: input.id,
      status: input.status,
      class: input.class,
      identifier: input.identifier,
      // TODO I'm not sure how these map?
      serviceType: input.serviceType[0],
      period: input.period,
      subject: input.subject,
      // TODO why is this automated wrong?
      // is the test data wrong?
      serviceProvider: input.serviceProvider,

      // TODO this won't map the system properly right now
      // because we don't handle codeable concepts very smartly
      serviceType: {
        coding: input.serviceType.coding.slice(0, 1),
      },
      type: input.type,
      // visitType: visitType,
    });

    // Handle the visit type extension manually
    util.addExtension(
      result.type[0],
      'http://moh.gov.et/fhir/hiv/StructureDefinition/encounter-visit-type',
      util.concept([
        visitType.valueString,
        'http://moh.gov.et/fhir/hiv/CodeSystem/encounter-visit-type-code-system',
      ])
    ),
      console.log(result);

    expect(result).to.eql(fixtures.ndr.encounter);
  });

  // This is based on a mapping rule which might not last forever
  // But it shows a cool option we have for mappings
  it.skip('should default the serviceProvider', () => {
    const result = builders.encounter('target-facility-encounter', {});

    const expected = {
      reference: 'Organization/Patient.managingOrganization',
    };
    expect(result.serviceProvider).to.eql(expected);
  });

  it('should map a single identifier string', () => {
    const result = builders.encounter('target-facility-encounter', {
      identifier: [{ value: 'bob' }],
    });

    const expected = [
      {
        value: 'bob',
      },
    ];
    expect(result.identifier).to.eql(expected);
  });

  it('should map an array of identifiers', () => {
    const result = builders.encounter('target-facility-encounter', {
      // this is the whole array (of one item)
      identifier: input.Encounter.resource.identifier,
    });

    const expected = [
      {
        value: '7834',
        system: 'http://cdr.aacahb.gov.et/Encounter',
      },
    ];
    expect(result.identifier).to.eql(expected);
  });
});

describe('Patient', () => {
  it('should convert CDR to NDR', () => {
    const input = fixtures.cdr.patient;

    // set system mappings - identifier should use this automagically
    util.setSystemMap({
      'http://cdr.aacahb.gov.et/SmartCareID':
        'http://moh.gov.et/fhir/hiv/identifier/SmartCareID',
      'http://cdr.aacahb.gov.et/MRN':
        'http://moh.gov.et/fhir/hiv/identifier/MRN',
      'http://cdr.aacahb.gov.et/UAN':
        'http://moh.gov.et/fhir/hiv/identifier/UAN',
    });

    // address mapping is a bit painful right now
    // but I think we can get this working from strings automatically
    const mapAddress = a => {
      if (/rural/i.test(a.text)) {
        const { text, ...address } = a;
        return {
          ...address,
          residentialType: util.concept(
            'Rural',
            util.coding('224804009', 'http://snomed.info/sct')
          ),
        };
      }
      return a;
    };
    
    const religion = util.findExtension(
      input,
      'http://hl7.org/fhir/StructureDefinition/patient-religion'
    ).valueCodeableConcept.coding[0];

    const result = builders.patient('patient', {
      id: input.id,
      religion: util.concept(
        religion.display,
        util.coding(
          religion.code,
          'http://terminology.hl7.org/CodeSystem/v3-ReligiousAffiliation'
        )
      ),
      identifier: input.identifier,
      name: input.name,
      telecom: input.telecom,
      gender: input.gender,
      birthDate: input.birthDate,
      maritalStatus: input.maritalStatus,
      managingOrganization: input.managingOrganization,
      address: input.address.map(mapAddress),
    });

    // console.log(result);

    expect(result).to.eql(fixtures.ndr.patient);
  });

  it('should set the address.residentialType extension', () => {
    const result = builders.patient('patient', {
      // address can be passed as a single object and it'll map to an array
      address: {
        line: ['my house'],
        // TODO should be able to get to here
        // residentialType: 'Rural',

        // ... but start here
        residentialType: {
          coding: [
            {
              system: 'http://snomed.info/sct',
              code: '224804009',
            },
          ],
          text: 'Rural',
        },
      },
    });

    expect(result.address).to.eql([
      {
        extension: [
          {
            url: 'http://moh.gov.et/fhir/hiv/StructureDefinition/residential-type',
            valueCodeableConcept: {
              coding: [
                {
                  system: 'http://snomed.info/sct',
                  code: '224804009',
                },
              ],
              text: 'Rural',
            },
          },
        ],
        line: ['my house'],
      },
    ]);
  });

  it('should set the religion extension', () => {
    const input = {
      religion: {
        // TODO: later, we we will out how to make it easier
        // to capture the coding here, because this is heavyweight
        coding: [
          {
            system:
              'http://terminology.hl7.org/CodeSystem/v3-ReligiousAffiliation',
            code: '1036',
          },
        ],
        text: 'Orthodox',
      },
    };

    const result = builders.patient('patient', {
      religion: input.religion,
    });

    expect(result.extension).to.eql([
      {
        url: 'http://hl7.org/fhir/StructureDefinition/patient-religion',
        valueCodeableConcept: {
          coding: [
            {
              system:
                'http://terminology.hl7.org/CodeSystem/v3-ReligiousAffiliation',
              code: '1036',
            },
          ],
          text: 'Orthodox',
        },
      },
    ]);
  });

  it.skip('should map a random patient', () => {
    const input = {};

    // First off, there's only one patient type, so this string is not neccessary
    // We can make the builder smarter there
    const result = builders.patient('patient', {
      id: i.id,
      identifier: i.identifier[0],
    });

    // TODO expected should soon be the output fixture
    // but obviously this test won't pass until we're done
    const expected = {
      id: 'e84781ed-5f02-40ac-8c97-e7280fb153e3',
      resourceType: 'Encounter',
      identifier: [
        {
          value: '7834',
          system: 'http://moh.gov.et/fhir/hiv/identifier/encounter',
        },
      ],
      serviceProvider: {
        reference: 'Organization/Patient.managingOrganization',
      },
      meta: {
        profile: [
          'http://moh.gov.et/fhir/hiv/StructureDefinition/target-facility-encounter',
        ],
      },
    };

    expect(result).to.eql(expected);

    // TODO result should equal output.Encounter
  });
});


describe('Observation', () => {
  it('should default code', () => {
    const o = builders.observation('patient-occupation-observation', {})

    expect(o.code).to.eql({ "coding": [{ "system": "http://loinc.org", "code": "85658-3" }] })
  })

  it('should default category', () => {
    const o = builders.observation('patient-occupation-observation', {})
    expect(o.category).to.eql({
      "coding": [
        {
          "system": "http://terminology.hl7.org/CodeSystem/observation-category",
          "code": "social-history"
        }
      ]
    })
  });

  it('should assign value', () => {
    const o = builders.observation('patient-occupation-observation', {
      value: util.concept(['value', 'system'])
    })
    expect(o.valueCodeableConcept).to.eql({
      "coding": [
        {
          "system": "system",
          "code": "value"
        }
      ]
    })
  });
})

describe('MedicationDispense', () => {
  // it('should map from a cdr MedicationDispense', () => {
  //   const input = fixtures.cdr.medicationDispense;

  //   // Try and find a concept or reference in the  source to define the medication
  //   let ref;
  //     ref = input.medicationCodeableConcept.coding.find(({ system }) => system === 'http://cdr.aacahb.gov.et/hiv-regimen-codes')
  //       ref = ref.code;
  //     }
  //   }
  //     ref = input.reference;
  //   }

  //   const handover = util.findExtension(input, 'http://cdr.aacahb.gov.et/dose-end-date')

  //   const result = builders.medicationDispense('arv-medication-dispense', {
  //     id: input.id,
  //     status: input.status,
  //     subject: input.subject,
  //     context: input.context,
  //     quantity: input.quantity,
  //     daysSupply: input.daysSupply,
  //     whenHandedOver: handover.valueDateTime,

  //     // TODO: need to support reference as a reference or codeable concept
  //     // also I don't see reference on the incoming data example? is it context.reference?
  //     medication: ref,


  //     // TODO this should refer to the MedicationRequest created
  //     // Do we know what that is?
  //     //authorizingPrescription: {}
  //   })

  //   expect(result).to.eql(fixtures.ndr.medicationDispense)


  // })
})

// medication request
describe("Medication", () => {
  it('should map from a cdr Medication', () => {
    const input = fixtures.cdr.medication;


    const [coding] = input.form.coding;

    const result = builders.medication('arv-regimen-medication', {

      id: input.id,

      // Not sure how strict to be on mapping here?
      // First we need to map the system and coding: looks like
      // NDR uses a fixed system ofhttp://cdr.aacahb.gov.et/hiv-regimen-codes I think?
      // (seems cosmetic)
      code: util.concept(coding.display, [coding.code, coding.system])

    })

    expect(result).to.eql(fixtures.ndr.medication)


  })
})

describe.skip("Care Plan", () => {
  it('should map from a cdr CarePlan', () => {
    const input = fixtures.cdr.careplan;


    const result = builders.carePlan('art-follow-up-careplan', {

      id: input.id,
      status: input.status,
      intent: input.intent,
      created: input.created,
      // maybe?
      reference: input.reference,
      subject: input.subject,
      encounter: input.encounter,

      // TODO how do we map activity?
      // need to handle backbone elements properly
      

    })

    // console.log(JSON.stringify(result, null, 2))
    
    // TODO category needs to be an array
    expect(result).to.eql(fixtures.ndr.careplan)


  })
});