# MITRE Caldera plugin: Atomic 

## Overview:

The Atomic plugin converts Red Canary’s Atomic Red Team tests from their open-source GitHub repository into CALDERA abilities for granular ATT&CK simulation.

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [AtomicCaldera](https://github.com/xenoscr/atomiccaldera)

### Context:
Atomic-level detection validation

### Known Limitations:
- ART tests only specify techniques they address. This plugin creates a mapping and import abilities under the corresponding tactic. Yet sometimes multiple tactics are a match, and we do not know which one the test addresses. This will be fixed in the future thanks to the ATT&CK sub-techniques. As of now, we use a new tactic category called "multiple".
- When a command/cleanup expands over multiple lines with one of them being a comment, it messes up the whole command/cleanup (as we reduce multiple lines into one with semi-colons).
- ART tests are not full adversary attack chains/ emulations.
- Some ART tests are incomplete.

## Installation:

1. Clone the repository to MITRE's Caldera "plugins" folder:
`cd <path to caldera/plugins>`
`git clone https://github.com/xenoscr/atomiccaldera.git`
2. Change directories:
`cd atomiccaldera`
3. Install required Python modules:
`pip install -r requirements.txt`
4. Clone the Red Canary Atomic Red Team repository:
`git clone https://github.com/redcanaryco/atomic-red-team.git`
5. Clone the MITRE CTI repository:
`git clone https://github.com/mitre/cti.git`
6. Edit the `conf/artconf.yml` file to update the paths to point to your Atomic Red Team and CTI repositories.
7. Edit Caldera's `local.yml` file and add `atomiccaldera` to the plugins section.

## Dependencies/Requirements:

1. Python 3.10+ with the following libraries installed:
- PyYAML - https://pyyaml.org/wiki/PyYAML
- STIX2 - https://github.com/oasis-open/cti-python-stix2
2. Atomic-Caldera requires the following repositories be stored locally somewhere:
- https://github.com/redcanaryco/atomic-red-team
- https://github.com/mitre/cti

## Getting Started:

The first time you access the Atomic plugin you will need to import the Atomic Red Team YAML files to populate Atomic Caldera's database. To do this click the "Add Abilities" button. Adding the abilities for the first time will take some time to complete, please be patient, the status will update when the import is completed.
 
### Selecting an Ability
To select an ability:
1. First select a tactic "Select ATT&CK tactic" drop down.
2. Next select the ability from the "Select ability" drop down.
 
After you have selected an ability you can use the left and right arrows to quickly move through the list of available abilities related to the selected tactic.
### Saving an Ability
If you have made changes to an ability and wish to save them:
1. Click the "Save Ability" button.
 
### Saving Variables
If you have made changes to variables and wish to save them:
1. Click the "Save Variables" button.
 
### Export a Single Ability
If you wish to export the selected ability only to Stockpile:
1. Click the Export Ability button.
  
### Export All Abilities
If you wish to export all of the abilities from Atomic Caldera to Stockpile:
1. Click the Export All Abilities button.
 
### Reloading Data (i.e. Start over)
If you wish to delete everything that has been imported and wish to start over, do so by:
1. Click the Reload Abilities button
2. Click the Yes button.
 
After clicking yes, it will then take some time for the abilities to complete reloading. NOTE: It is necessary to restart Caldera to view the new abilities. At the moment there is no way to force Chain to reload its database from the GUI.

### Additional Note
- When importing tests from Atomic Red Team, this plugin also catches `$PathToAtomicsFolder` usages pointing to an existing file.  It then imports the files as payloads and fixes path usages. Note other usages are not handled. If a path with `$PathToAtomicsFolder` points to an existing directory or an unexisting file, we will not process it any further and ingest it "as it is". Examples of such usages below:
- https://github.com/redcanaryco/atomic-red-team/blob/a956d4640f9186a7bd36d16a63f6d39433af5f1d/atomics/T1022/T1022.yaml#L99
- https://github.com/redcanaryco/atomic-red-team/blob/ab0b391ac0d7b18f25cb17adb330309f92fa94e6/atomics/T1056/T1056.yaml#L24
