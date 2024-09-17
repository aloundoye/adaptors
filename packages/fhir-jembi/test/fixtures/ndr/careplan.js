export default {
  "resourceType": "CarePlan",
  "id": "beffffab-5aec-43ad-9c31-3ecb90246b82CarePlan171",
  "meta": {
      "profile": [
          "http://moh.gov.et/fhir/hiv/StructureDefinition/art-follow-up-careplan"
      ]
  },
  "status": "active",
  "intent": "order",
  "category": [
      {
          "coding": [
              {
                  "system": "http://loinc.org",
                  "code": "LP66375-4"
              }
          ],
          // "text": "ART" TODO I think we need to support this?
      }
  ],
  "subject": {
      "reference": "Patient/e6e0c715-a0d4-48ac-8112-f84ebd39d61b"
  },
  "encounter": {
      "reference": "Encounter/30120"
  },
  "created": "2014-09-21",
  // TODO need to handle this
//   "activity": [
//       {
//           "extension": [
//               {
//                   "url": "http://moh.gov.et/fhir/hiv/StructureDefinition/care-plan-next-visit",
//                   "valueDateTime": "2024-03-20"
//               },
//               {
//                   "url": "http://moh.gov.et/fhir/hiv/StructureDefinition/arv-adherence",
//                   "valueReference": {
//                       "reference": "Observation/FairARVAdherenceExample"
//                   }
//               }
//           ],
//           "reference": {
//               "reference": "MedicationRequest/ARVMedicationRequestInitiatedARTExample"
//           }
//       }
//   ]
};
